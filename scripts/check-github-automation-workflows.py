"""Check the repository-wide label-writer concurrency contract."""

from pathlib import Path
import json


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = [
    ROOT / ".github/workflows/pr-automation.yml",
    ROOT / ".github/workflows/ci-diagnostics.yml",
    ROOT / ".github/workflows/repository-reconciliation.yml",
]
GROUP = "aster-repository-label-writers"


def main() -> None:
    for path in WORKFLOWS:
        text = path.read_text(encoding="utf-8")
        if f"group: {GROUP}" not in text:
            raise SystemExit(f"{path}: missing shared label-writer concurrency group")
        if "cancel-in-progress: false" not in text:
            raise SystemExit(f"{path}: label writer must retain in-flight work")
        if "queue: max" not in text:
            raise SystemExit(f"{path}: label writer must retain queued workflow runs")
    config = json.loads((ROOT / ".github/aster-automation.json").read_text(encoding="utf-8"))
    high_risk = next(rule for rule in config["labels"]["rules"] if rule["label"] == "Risk: High")
    for entry in ("crates/aster_acme/src/crypto.rs", "crates/aster_acme/src/transport.rs", "crates/aster_acme/src/storage.rs"):
        if entry not in high_risk["paths"]:
            raise SystemExit(f"Risk: High is missing module entry path {entry}")
    for entry in ("crates/aster_acme/src/crypto/**", "crates/aster_acme/src/transport/**", "crates/aster_acme/src/storage/**"):
        if entry not in high_risk["paths"]:
            raise SystemExit(f"Risk: High directory coverage was removed: {entry}")
    print("GitHub automation workflow concurrency contract: OK")


if __name__ == "__main__":
    main()
