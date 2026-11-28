"""Verify chain selection deadline and terminal restoration through a PTY."""
import errno
import os
from pathlib import Path
import pty
import select
import subprocess
import termios
import time
import json

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = "commands::cert::execute::chain_selector::tests::bounded_chain_prompt_child"


def test_binary():
    build = subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            "aster_acme_cli",
            "--locked",
            "--no-run",
            "--message-format=json",
        ],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    for line in build.stdout.splitlines():
        item = json.loads(line)
        if (
            item.get("reason") == "compiler-artifact"
            and item.get("executable")
            and item.get("profile", {}).get("test")
        ):
            return item["executable"]
    raise RuntimeError("could not locate the CLI test executable")


def main():
    binary = test_binary()
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    process = subprocess.Popen(
        [binary, "--exact", FIXTURE, "--ignored", "--nocapture"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        cwd=ROOT,
        env={**os.environ, "TERM": "xterm-256color"},
    )
    transcript = bytearray()
    deadline = time.monotonic() + 10
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    transcript.extend(os.read(master, 65536))
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
            if process.poll() is not None:
                drain_deadline = time.monotonic() + 0.5
                while time.monotonic() < drain_deadline and select.select(
                    [master], [], [], 0.05
                )[0]:
                    try:
                        transcript.extend(os.read(master, 65536))
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                break
        assert process.poll() is not None, bytes(transcript).decode(errors="replace")
        assert process.wait(timeout=1) == 0, bytes(transcript).decode(errors="replace")
        assert b"CHAIN_TERMINAL_TIMEOUT_DONE" in transcript, transcript
        assert b"Certificate chain:" in transcript, transcript
        assert termios.tcgetattr(slave) == before, "terminal mode was not restored"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        os.close(slave)
    print("Certificate chain PTY deadline: passed")


if __name__ == "__main__":
    main()
