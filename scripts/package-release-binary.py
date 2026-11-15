"""Strip a release binary while preserving a symbol artifact for diagnostics."""
import argparse
import platform
import shutil
import subprocess
from pathlib import Path


def run(command):
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def package_macos(binary, artifact_dir):
    symbols = artifact_dir / f"{binary.name}.symbols"
    shutil.copy2(binary, symbols)
    subprocess.run(["strip", str(binary)], check=True)
    uuid_output = run(["dwarfdump", "--uuid", str(binary), str(symbols)])
    (artifact_dir / f"{binary.name}.uuid").write_text(uuid_output, encoding="utf-8")
    return symbols


def package_linux(binary, artifact_dir):
    debug = artifact_dir / f"{binary.name}.debug"
    subprocess.run(["objcopy", "--only-keep-debug", str(binary), str(debug)], check=True)
    subprocess.run(["strip", "--strip-all", str(binary)], check=True)
    subprocess.run(["objcopy", f"--add-gnu-debuglink={debug}", str(binary)], check=True)
    return debug


def package(binary, artifact_dir, system):
    if not binary.is_file():
        raise SystemExit(f"release binary does not exist: {binary}")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if system == "Darwin":
        return package_macos(binary, artifact_dir)
    if system == "Linux":
        return package_linux(binary, artifact_dir)
    raise SystemExit(
        "Windows release symbol packaging is not automated yet; determine the PDB "
        "and binary pairing workflow before publishing Windows artifacts."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="release binary to strip in place")
    parser.add_argument("artifact_dir", type=Path, help="directory for the symbol artifact")
    parser.add_argument(
        "--system",
        choices=["Darwin", "Linux"],
        default=platform.system(),
        help="override the host system for release automation tests",
    )
    arguments = parser.parse_args()
    artifact = package(arguments.binary, arguments.artifact_dir, arguments.system)
    print(f"Created symbol artifact: {artifact}")


if __name__ == "__main__":
    main()
