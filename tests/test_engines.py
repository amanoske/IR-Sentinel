from pathlib import Path

import pytest

from ir_sentinel.defense import build, replay
from ir_sentinel.engines import discover
from ir_sentinel.investigation import investigate

pytestmark = pytest.mark.engines


@pytest.mark.parametrize("engine", ["suricata", "zeek"])
def test_real_rules_match_case_but_not_benign(store, captures, engine):
    if not discover()["tshark"] or not discover()[engine]:
        pytest.skip(f"Requires installed TShark and {engine}")
    result = investigate(store, path=str(captures[0]))
    assert result.engine_status["tshark"] == "ok"
    assert result.engine_status[engine] == "ok"
    assert any(f.refs == ["packet:4"] for f in result.findings)
    candidate = build(store, result.case_id, engine)
    checked = replay(store, result.case_id, Path(candidate.path).stem, str(captures[1]))
    assert checked.validation["status"] == "validated_on_supplied_samples", checked.model_dump()
    assert checked.validation["runs"]["case"]["matches"] > 0
    assert checked.validation["runs"]["benign"]["matches"] == 0
    assert not list(store.root.rglob("*.pcap")) and not list(store.root.rglob("evidence.bin"))
    captures[0].write_bytes(b"changed after analysis")
    with pytest.raises(ValueError, match="changed"):
        replay(store, result.case_id, Path(candidate.path).stem)
