"""Native account terms consent through loopback CA, real storage and terminal prompts."""
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
FIXTURE = "commands::account::execute::tests::terminal_terms_consent_child"
UPDATE_FIXTURE = "commands::account::mutation::tests::terminal_update_consent_child"
CURRENT = b"Do you agree to these terms?"
FUTURE = b"Automatically accept future CA terms updates?"


def run_case(binary, mode, answers, fixture=FIXTURE, done_prefix="ACCOUNT_TERMS_DONE"):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    process = subprocess.Popen(
        [binary, "--exact", fixture, "--ignored", "--nocapture"],
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
                if mode == "update-combined-conflict" and answers[sent][0] == b"Enable automatic terms updates?":
                    record_match = re.search(rb"ACCOUNT_UPDATE_RECORD=([^\r\n]+)", output)
                    assert record_match is not None, repr(bytes(output))
                    record = Path(record_match[1].decode())
                    content = record.read_text(encoding="utf-8")
                    old = 'accepted_terms_url = "https://ca.example/terms/v1"'
                    assert content.count(old) == 1, content
                    record.write_text(content.replace(old, 'accepted_terms_url = "https://ca.example/terms/v3"'), encoding="utf-8")
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
        assert f"{done_prefix} {mode}".encode() in output, repr(bytes(output))
        if mode == "yes":
            assert CURRENT not in output and FUTURE not in output, repr(bytes(output))
        if mode == "update-combined-yes":
            assert b"Replace these contacts?" not in output, repr(bytes(output))
            assert b"Enable automatic terms updates?" not in output, repr(bytes(output))
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
    enable = b"Enable automatic terms updates?"
    contacts = (b"Replace these contacts?", b"y\r")
    menu = (b"Update which account preference?", b"\x1b[B\x1b[B\r")
    update_cases = [
        ("update-grant", [(enable, b"y\r")]),
        ("update-deny", [(enable, b"n\r")]),
        ("update-default-deny", [(enable, b"\r")]),
        ("update-cancel", [(enable, b"\x03")]),
        ("update-revoke-grant", [(b"Disable automatic terms updates?", b"y\r")]),
        ("update-revoke-deny", [(b"Disable automatic terms updates?", b"n\r")]),
        ("update-revoke-cancel", [(b"Disable automatic terms updates?", b"\x03")]),
        ("update-menu-grant", [menu, (enable, b"y\r")]),
        ("update-menu-deny", [menu, (enable, b"n\r")]),
        ("update-menu-profile", [(b"Update which account preference?", b"\x1b[B\r"),
                                 (b"Default certificate profile:", b"\x1b[B\r")]),
        ("update-combined-grant", [contacts, (enable, b"y\r")]),
        ("update-combined-deny", [contacts, (enable, b"n\r")]),
        ("update-combined-cancel", [contacts, (enable, b"\x03")]),
        ("update-combined-yes", []),
        ("update-combined-conflict", [contacts, (enable, b"y\r")]),
        ("update-profile-deny", [(b"Save this profile preference?", b"n\r")]),
    ]
    for mode, answers in update_cases:
        run_case(binary, mode, answers, UPDATE_FIXTURE, "ACCOUNT_UPDATE_DONE")
    print("Account terms PTY: 5 registration and 16 update scenarios passed (consent, revocation, default no, menu snapshot, combined scopes, concurrent consent conflict, partial cancellation, finish exit 130, terminal restoration)")


if __name__ == "__main__":
    main()
