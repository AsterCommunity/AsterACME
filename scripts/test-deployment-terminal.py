"""Native PKCS#12 hidden-password input, cancellation and JSON prompt suppression."""
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
FIXTURE = "commands::cert::deployment::tests::pkcs12::password_terminal_child"
PROMPT = b"PKCS#12 password for deployment"
SECRET = b"pty-secret-55"


def run_case(binary, mode):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    process = subprocess.Popen(
        [binary, "--exact", FIXTURE, "--ignored", "--nocapture"],
        stdin=slave, stdout=slave, stderr=slave, cwd=ROOT,
        env={**os.environ, "ASTER_P12_TERMINAL_MODE": mode, "NO_COLOR": "1", "TERM": "xterm-256color"},
    )
    transcript = bytearray()
    sent = 0
    consumed = 0
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not data:
                    break
                transcript.extend(data)
            if mode not in ("json", "add") and sent == 0 and PROMPT in transcript:
                consumed = len(transcript)
                os.write(master, SECRET + b"\r" if mode == "success" else b"\x03")
                sent += 1
            elif mode == "success" and sent == 1 and b"Confirmation:" in transcript[consumed:]:
                os.write(master, SECRET + b"\r")
                sent += 1
            if process.poll() is not None:
                while select.select([master], [], [], 0.05)[0]:
                    transcript.extend(os.read(master, 65536))
                break
        assert process.poll() is not None, bytes(transcript).decode(errors="replace")
        assert process.wait(timeout=1) == 0, bytes(transcript).decode(errors="replace")
        assert f"P12_TERMINAL_DONE {mode}".encode() in transcript, repr(bytes(transcript))
        assert SECRET not in transcript, "password appeared in terminal output"
        if mode in ("json", "add"):
            assert PROMPT not in transcript, "non-run or JSON command prompted for a password"
        else:
            assert sent == (2 if mode == "success" else 1)
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
    for mode in ["success", "cancel", "json", "add"]:
        run_case(binary, mode)
    print("PKCS#12 PTY: 4 scenarios passed (hidden password and confirmation, cancel, JSON and add never prompt)")


if __name__ == "__main__":
    main()
