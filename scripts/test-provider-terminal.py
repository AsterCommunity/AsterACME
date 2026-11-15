"""Native Unix PTY checks for shared provider selection and human report colors."""
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
FIXTURE = "commands::provider::tests::provider_selection_child"
ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")


def run_case(binary, mode, prompts, color, cancelled=False):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    environment = {**os.environ, "ASTER_PROVIDER_TEST_MODE": mode, "TERM": "xterm-256color"}
    environment.pop("NO_COLOR", None)
    if not color:
        environment["NO_COLOR"] = "1"
    fixture = "commands::cert::interaction::tests::interactive_issue_child" if mode == "issue" else FIXTURE
    process = subprocess.Popen(
        [binary, "--exact", fixture, "--ignored", "--nocapture"],
        stdin=slave, stdout=slave, stderr=slave, cwd=ROOT, env=environment,
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
            if sent < len(prompts) and prompts[sent][0] in output[consumed:]:
                consumed = len(output)
                os.write(master, prompts[sent][1])
                sent += 1
            if process.poll() is not None:
                while select.select([master], [], [], 0.05)[0]:
                    output.extend(os.read(master, 65536))
                break
        assert process.poll() is not None, (mode, sent, bytes(output).decode(errors="replace"))
        assert process.wait(timeout=1) == 0, bytes(output).decode(errors="replace")
        assert sent == len(prompts), repr(bytes(output))
        visible = ANSI.sub(b"", bytes(output)).replace(b"\r", b"")
        assert b"secret-sentinel" not in output, repr(visible)
        if cancelled:
            assert b"INPUT_CANCELLED" in visible, repr(visible)
            assert b"REPORT_BEGIN" not in visible, repr(visible)
        elif mode == "issue":
            assert b"SELECTED=cf-test" in visible, repr(visible)
        elif mode == "cleanup":
            assert b"No terminal DNS publication cleanup is pending" in visible, repr(visible)
        elif mode == "remove":
            assert b"Removed provider profile cf-test" in visible, repr(visible)
        else:
            report = bytes(output).split(b"REPORT_BEGIN", 1)[1].split(b"REPORT_END", 1)[0]
            plain = ANSI.sub(b"", report)
            name = b"cf-new" if mode == "add" else b"cf-test"
            assert name in plain and b"alpha" not in plain, repr(plain)
            assert b"Profile file:" in plain and b"providers/" + name + b".toml" in plain, repr(plain)
            assert (b"\x1b[36mProfile file:" in report) == color, repr(report)
        assert termios.tcgetattr(slave) == before, "terminal mode was not restored"
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
    selector = (b"DNS provider profile:", b"cf-test\r")
    cases = 0
    for mode in ["show", "issue", "cleanup", "remove", "add"]:
        prompts = [(b"DNS provider profile name:", b"cf-new\r"), (b"Provider executable path:", os.fsencode(binary) + b"\r")] if mode == "add" else [selector]
        if mode == "remove":
            prompts += [(b"Remove this provider profile?", b"y\r")]
        for color in [False, True]:
            run_case(binary, mode, prompts, color)
            cases += 1
        run_case(binary, mode, [(prompts[0][0], b"\x03")], False, cancelled=True)
        cases += 1
    for keys in [b"\r", b"n\r", b"\x03"]:
        run_case(binary, "remove", [selector, (b"Remove this provider profile?", keys)], False, cancelled=True)
        cases += 1
    run_case(binary, "add", [(b"DNS provider profile name:", b"cf-new\r"), (b"Provider executable path:", b"\x03")], False, cancelled=True)
    cases += 1
    update = [selector, (b"Edit provider profile:", b"Arguments\r"), (b"Edit arguments:", b"Add value\r"),
              (b"Argument value (passed exactly, without shell parsing):", b"--label=hello world\r"),
              (b"Edit arguments:", b"Back to profile\r")]
    for color in [False, True]:
        run_case(binary, "update", update + [(b"Edit provider profile:", b"Save changes\r")], color)
        cases += 1
    for back in [b"\x1b", b"Back\r"]:
        navigation = update[:4] + [(b"Edit arguments:", b"Remove value\r"), (b"Remove which value?", back),
                                  (b"Edit arguments:", b"Back to profile\r"), (b"Edit provider profile:", b"Save changes\r")]
        run_case(binary, "update", navigation, False)
        cases += 1

    for prompts in [[selector, (b"Edit provider profile:", b"\x03")],
                    update + [(b"Edit provider profile:", b"Cancel\r")],
                    update[:2] + [(b"Edit arguments:", b"\x03")]]:
        run_case(binary, "update", prompts, False, cancelled=True)
        cases += 1

    print(f"Provider PTY: {cases} scenarios passed (add/show/cleanup/remove/update/issue, search, colors, default-no/cancel, terminal restoration)")


if __name__ == "__main__":
    main()
