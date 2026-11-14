"""Native Unix PTY checks: prompt placement, echo, edits and terminal restoration."""
import errno
import json
import os
from pathlib import Path
import pty
import re
import select
import subprocess
import termios
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = "commands::cert::validation::manual::tests::terminal_confirmation_child"
PROMPT = b"Are these HTTP challenge files publicly available?"


def run_case(binary, mode, keys, echoed):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    process = subprocess.Popen(
        [binary, "--exact", FIXTURE, "--ignored", "--nocapture"],
        stdin=slave, stdout=slave, stderr=slave, cwd=ROOT,
        env={**os.environ, "ASTER_CONFIRM_TEST_MODE": mode, "NO_COLOR": "1"},
    )
    output = bytearray()
    sent = False
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output.extend(chunk)
            if not sent and PROMPT in output:
                if keys:
                    os.write(master, keys)
                if mode == "paste":
                    time.sleep(0.2)
                    assert process.poll() is None, "pasted newline must not submit the answer"
                    os.write(master, b"\r")
                sent = True
            if process.poll() is not None:
                # Drain remaining writes before checking the full transcript.
                while select.select([master], [], [], 0.05)[0]:
                    output.extend(os.read(master, 65536))
                break
        assert process.wait(timeout=1) == 0, bytes(output).decode(errors="replace")
        assert sent, repr(bytes(output))
        visible = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", bytes(output))
        assert b"(y/N)" in visible or b"[y/N]" in visible, repr(visible)
        if echoed:
            assert PROMPT + b" " + echoed in visible, repr(visible)
        assert f"CONFIRM_RESTORED mode={mode}".encode() in output
        after = termios.tcgetattr(slave)
        assert after == before, f"terminal attributes not restored: {mode}"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        os.close(slave)


def main():
    build = subprocess.run(
        ["cargo", "test", "-p", "aster_acme_cli", "--locked", "--no-run", "--message-format=json"],
        cwd=ROOT, check=True, text=True, encoding="utf-8", capture_output=True,
    )
    binaries = [item["executable"] for line in build.stdout.splitlines()
                if (item := json.loads(line)).get("reason") == "compiler-artifact"
                and item.get("executable") and item.get("profile", {}).get("test")]
    binary, = binaries
    for mode, keys, echoed in [
        ("yes", b"y\r", b"Yes"), ("no", b"n\r", b"No"),
        ("yes-word", b"yes\r", b"Yes"), ("no-word", b"no\r", b"No"),
        ("default", b"\r", b"No"), ("replace", b"n\x7fy\r", b"Yes"),
        ("erase", b"y\x7f\r", b"No"),
        ("uppercase", b"YES\r", b"Yes"),
        ("insert", b"ys\x1b[De\r", b"Yes"),
        ("delete", b"xno\x1b[H\x1b[3~\x1b[F\r", b"No"),
        ("invalid", b"maybe\r" + b"\x7f" * 5 + b"yes\r", b"Yes"),
        ("limit", b"x" * 64 + b"\x7f" * 8 + b"y\r", b"Yes"),
        ("paste", b"\x1b[200~yes\r\n\x1b[201~", b"Yes"),
        ("escape", b"\x1b", b""), ("ctrl-c", b"\x03", b""),
        ("timeout", b"", b""), ("cancel", b"", b""),
        ("shutdown", b"", b""),
    ]:
        run_case(binary, mode, keys, echoed)
    print("Confirmation PTY: 18 scenarios passed (answers/edits/input limits/paste, idle deadline/cancel/shutdown and terminal restoration)")


if __name__ == "__main__":
    main()
