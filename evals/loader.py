"""Read a scenario YAML (frozen schema) and return (seed, expect)."""
from pathlib import Path

import yaml

FAMILIES = {"benign", "direct_injection", "indirect_injection",
            "exfiltration", "scope_escalation", "obfuscation"}


class ScenarioError(ValueError):
    pass


def load_scenario(path) -> dict:
    path = Path(path)
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        raise ScenarioError(f"{path}: not a mapping")
    for key in ("id", "family", "seed", "expect"):
        if key not in data:
            raise ScenarioError(f"{path}: missing {key!r}")
    if data["family"] not in FAMILIES:
        raise ScenarioError(f"{path}: unknown family {data['family']!r}")
    data["seed"] = data["seed"] or {}
    data["expect"] = data["expect"] or {}
    return data


def load(path) -> tuple[dict, dict]:
    data = load_scenario(path)
    return data["seed"], data["expect"]
