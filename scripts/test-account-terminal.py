"""Native account terms consent through loopback CA, real storage and terminal prompts."""
import errno
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import termios
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = "commands::account::execute::tests::terminal_terms_consent_child"
CURRENT = b"Do you agree to these terms?"
FUTURE = b"Automatically accept future CA terms updates?"


def run_case(binary, mode, answers):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    process = subprocess.Popen(
        [binary, "--exact", FIXTURE, "--ignored", "--nocapture"],
        stdin=slave, stdout=slave, stderr=slave, cwd=ROOT,
        env={**os.environ, "ASTER_ACCOUNT_TERMS_TEST_MODE": mode,
             "NO_COLOR": "1", "TERM": "xterm-256color"},
    )
    output = bytearray()
    sent = 0
    consumed = 0
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
            if sent < len(answers) and answers[sent][0] in output[consumed:]:
                consumed = len(output)
                os.write(master, answers[sent][1])
                sent += 1
            if process.poll() is not None:
                while select.select([master], [], [], 0.05)[0]:
                    output.extend(os.read(master, 65536))
                break
        assert process.poll() is not None, bytes(output).decode(errors="replace")
        assert process.wait(timeout=1) == 0, bytes(output).decode(errors="replace")
        assert sent == len(answers), repr(bytes(output))
        assert f"ACCOUNT_TERMS_DONE {mode}".encode() in output, repr(bytes(output))
        if mode == "yes":
            assert CURRENT not in output and FUTURE not in output, repr(bytes(output))
        assert termios.tcgetattr(slave) == before, "terminal state was not restored"
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
    for mode, answers in [
        ("yes", []),
        ("grant", [(CURRENT, b"y\r"), (FUTURE, b"y\r")]),
        ("default", [(CURRENT, b"y\r"), (FUTURE, b"\r")]),
        ("deny", [(CURRENT, b"y\r"), (FUTURE, b"n\r")]),
        ("cancel", [(CURRENT, b"y\r"), (FUTURE, b"\x03")]),
    ]:
        run_case(binary, mode, answers)
    print("Account terms PTY: 5 scenarios passed (yes skips delegation, explicit consent, default no, decline, cancel)")


if __name__ == "__main__":
    main()
