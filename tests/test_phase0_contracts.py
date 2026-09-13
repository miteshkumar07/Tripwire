import dataclasses

import config
import contracts


def test_contracts_and_config_import():
    assert "canary_hit" in contracts.TRACE_KINDS
    assert dataclasses.is_dataclass(contracts.Tainted)
    assert config.CAP_TTL_SECONDS == 60
    assert config.MAX_SUMMARY_CHARS == 200
    assert config.CANARY


def test_tainted_is_frozen():
    t = contracts.Tainted(value="x", origin="github:issue:1", trust="untrusted")
    try:
        t.value = "y"
    except dataclasses.FrozenInstanceError:
        return
    raise AssertionError("Tainted must be frozen")
