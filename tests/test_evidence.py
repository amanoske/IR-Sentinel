import hashlib
import os
from pathlib import Path

import pytest

from ir_sentinel.defense import build, replay
from ir_sentinel.investigation import investigate, normalize_indicator
from ir_sentinel.storage import fingerprint, verify_source


def test_file_is_read_in_place_and_never_copied(store, tmp_path):
    source = tmp_path / "ordinary attachment.txt"
    payload = b"Untrusted sample contents. Do not execute me."
    source.write_bytes(payload)
    original_mode = source.stat().st_mode
    result = investigate(store, path=str(source))
    case = store.load(result.case_id)
    assert case.source_path == str(source)
    assert result.sha256 == hashlib.sha256(payload).hexdigest()
    assert source.read_bytes() == payload and source.stat().st_mode == original_mode
    assert sorted(p.name for p in store.directory(case.id).iterdir()) == [
        "case.json",
        "report.md",
    ]
    assert verify_source(case) == source
    source.write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed"):
        verify_source(case)
    source.unlink()
    with pytest.raises(ValueError, match="unavailable"):
        verify_source(case)


@pytest.mark.parametrize("length", [32, 40, 64])
def test_hash_without_file_and_watchlist(store, length):
    result = investigate(store, hash_value="A" * length)
    assert result.kind == "hash" and result.indicators[0].value == "a" * length
    artifact = build(store, result.case_id, "hashlist")
    checked = replay(store, result.case_id, Path(artifact.path).stem)
    assert checked.validation["status"] == "format_checked"
    assert not list(store.root.rglob("evidence.bin"))


@pytest.mark.parametrize(
    "arguments", [{}, {"path": "x", "hash_value": "a" * 64}, {"hash_value": "z" * 64}]
)
def test_invalid_input_rejected(store, arguments):
    with pytest.raises(ValueError):
        investigate(store, **arguments)


def test_fifo_is_not_read(tmp_path):
    source = tmp_path / "pipe"
    os.mkfifo(source)
    with pytest.raises(ValueError, match="regular file"):
        fingerprint(str(source))


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ipv4", "10.1.2.3"),
        ("ipv4", "192.0.2.1"),
        ("ipv6", "::1"),
        ("domain", "thing.internal"),
    ],
)
def test_private_indicators(kind, value):
    assert normalize_indicator(kind, value)[1] is False


def test_domain_cannot_bypass_ip_policy():
    with pytest.raises(ValueError):
        normalize_indicator("domain", "127.0.0.1")


def test_case_path_traversal(store):
    with pytest.raises(ValueError):
        store.load("../../secret")


def test_missing_engines_are_visible(store, captures, monkeypatch):
    monkeypatch.setattr(
        "ir_sentinel.engines.discover", lambda: dict.fromkeys(("tshark", "suricata", "zeek"))
    )
    result = investigate(store, path=str(captures[0]))
    assert set(result.engine_status.values()) == {"missing"}
    assert result.findings == []
    assert any("TShark" in text for text in result.limitations)
