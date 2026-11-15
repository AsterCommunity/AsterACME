"""Native PTY checks against the built CLI; no provider process or CA is invoked."""
import errno
import os
from pathlib import Path
import pty
import re
import select
import subprocess
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parents[1]
ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")


def prepare(binary, root):
    for name in ["alpha", "cf-test"]:
        subprocess.run(
            [binary, "provider", "add", name, "--exec", "/usr/bin/true",
             "--data-dir", root, "--json"],
            cwd=ROOT, check=True, capture_output=True,
        )


def command(binary, mode, root):
    common = ["--data-dir", root]
    if mode in {"show", "cleanup", "remove", "update"}:
        return [binary, "provider", mode, *common]
    if mode == "add":
        return [binary, "provider", "add", *common]
    if mode == "issue":
        return [binary, "cert", "issue", "-c", "dns_external", "-d", "example.com", *common]
    raise AssertionError(mode)


def run_case(binary, mode, prompts, color, cancelled=False):
    with tempfile.TemporaryDirectory(prefix="aster-provider-pty-") as directory:
        prepare(binary, directory)
        master, slave = pty.openpty()
        before = termios.tcgetattr(slave)
        environment = {**os.environ, "TERM": "xterm-256color"}
        environment.pop("NO_COLOR", None)
        if not color:
            environment["NO_COLOR"] = "1"
        process = subprocess.Popen(
            command(binary, mode, directory), stdin=slave, stdout=slave, stderr=slave,
            cwd=ROOT, env=environment,
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
            expected_status = 130 if cancelled else (1 if mode == "issue" else 0)
            assert process.poll() is not None, (mode, sent, bytes(output).decode(errors="replace"))
            assert process.wait(timeout=1) == expected_status, bytes(output).decode(errors="replace")
            assert sent == len(prompts), repr(bytes(output))
            visible = ANSI.sub(b"", bytes(output)).replace(b"\r", b"")
            if cancelled:
                assert b"Canceled; inspect saved state" in visible, repr(visible)
            elif mode == "issue":
                assert b"No local account named" in visible, repr(visible)
            elif mode == "cleanup":
                assert b"No terminal DNS publication cleanup is pending" in visible, repr(visible)
            elif mode == "remove":
                assert b"Removed provider profile cf-test" in visible, repr(visible)
            elif mode == "add":
                report = bytes(output)
                assert b"cf-new" in visible and b"providers/cf-new.toml" in visible, repr(visible)
                assert (b"\x1b[36mProfile file:" in report) == color, repr(report)
            elif mode == "show":
                report = bytes(output)
                details = ANSI.sub(b"", report).replace(b"\r", b"").rsplit(b"\nDNS provider profile:\n", 1)[-1]
                assert b"cf-test" in details and b"alpha" not in details, repr(details)
                assert b"Profile file:" in details and b"providers/cf-test.toml" in details, repr(details)
                assert (b"\x1b[36mProfile file:" in report) == color, repr(report)
            elif mode == "update" and not cancelled:
                saved = subprocess.run(
                    [binary, "provider", "show", "cf-test", "--data-dir", directory, "--json"],
                    cwd=ROOT, check=True, capture_output=True,
                )
                assert b"--label=hello world" in saved.stdout
            assert termios.tcgetattr(slave) == before, "terminal mode was not restored"
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)
            os.close(slave)


def main():
    subprocess.run(["cargo", "build", "-p", "aster_acme_cli", "--locked"], cwd=ROOT, check=True)
    binary = str(ROOT / "target/debug/aster-acme")
    selector = (b"DNS provider profile:", b"cf-test\r")
    cases = 0
    for mode in ["show", "issue", "cleanup", "remove", "add"]:
        prompts = [(b"DNS provider profile name:", b"cf-new\r"),
                   (b"Provider executable path:", b"/usr/bin/true\r")] if mode == "add" else [selector]
        if mode == "remove":
            prompts += [(b"Remove this provider profile?", b"y\r")]
        for color in [False, True]:
            run_case(binary, mode, prompts, color)
            cases += 1
        run_case(binary, mode, [(prompts[0][0], b"\x03")], False, cancelled=True)
        cases += 1
    for keys in [b"\r", b"n\r"]:
        run_case(binary, "remove", [selector, (b"Remove this provider profile?", keys)], False, cancelled=True)
        cases += 1
    run_case(binary, "add", [(b"DNS provider profile name:", b"cf-new\r"),
                              (b"Provider executable path:", b"\x03")], False, cancelled=True)
    cases += 1
    update = [selector, (b"Edit provider profile:", b"Arguments\r"),
              (b"Edit arguments:", b"Add value\r"),
              (b"Argument value (passed exactly, without shell parsing):", b"--label=hello world\r"),
              (b"Edit arguments:", b"Back to profile\r")]
    for color in [False, True]:
        run_case(binary, "update", update + [(b"Edit provider profile:", b"Save changes\r")], color)
        cases += 1
    for back in [b"\x1b", b"Back\r"]:
        navigation = update[:4] + [(b"Edit arguments:", b"Remove value\r"),
                                    (b"Remove which value?", back),
                                    (b"Edit arguments:", b"Back to profile\r"),
                                    (b"Edit provider profile:", b"Save changes\r")]
        run_case(binary, "update", navigation, False)
        cases += 1
    for prompts in [[selector, (b"Edit provider profile:", b"\x03")],
                    update + [(b"Edit provider profile:", b"Cancel\r")],
                    update[:2] + [(b"Edit arguments:", b"\x03")]]:
        run_case(binary, "update", prompts, False, cancelled=True)
        cases += 1
    print(f"Provider PTY: {cases} scenarios passed (real CLI add/show/cleanup/remove/update/issue, colors, cancel and terminal restoration)")


if __name__ == "__main__":
    main()
