"""Check the repository-wide label-writer concurrency contract."""

from pathlib import Path
import json
import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = [
    ROOT / ".github/workflows/pr-automation.yml",
    ROOT / ".github/workflows/ci-diagnostics.yml",
    ROOT / ".github/workflows/repository-reconciliation.yml",
]
GROUP = "aster-repository-label-writers"


class StrictSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            raise yaml.constructor.ConstructorError(
                None, None, "expected a mapping node", node.start_mark
            )
        self.flatten_mapping(node)
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable key",
                    key_node.start_mark,
                ) from error
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def workflow_concurrency(path: Path) -> dict[str, str]:
    """Parse the workflow-level concurrency mapping used by this contract."""
    workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=StrictSafeLoader)
    concurrency = workflow.get("concurrency") if isinstance(workflow, dict) else None
    if not isinstance(concurrency, dict):
        raise SystemExit(f"{path}: missing workflow-level concurrency mapping")
    if set(concurrency) != {"group", "cancel-in-progress", "queue"}:
        raise SystemExit(f"{path}: concurrency must contain exactly group, cancel-in-progress and queue")
    if any(not isinstance(value, (str, bool)) for value in concurrency.values()):
        raise SystemExit(f"{path}: concurrency values must be scalar")
    return concurrency


def validate_concurrency(path: Path) -> None:
    concurrency = workflow_concurrency(path)
    if concurrency["group"] != GROUP:
        raise SystemExit(f"{path}: missing shared label-writer concurrency group")
    if concurrency["cancel-in-progress"] is not False:
        raise SystemExit(f"{path}: label writer must retain in-flight work")
    if concurrency["queue"] != "max":
        raise SystemExit(f"{path}: label writer must retain queued workflow runs")


def main() -> None:
    for path in WORKFLOWS:
        validate_concurrency(path)
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
