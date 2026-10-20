import importlib.util
from pathlib import Path

import pytest

from ir_sentinel.storage import Store


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "cases")


@pytest.fixture
def captures(tmp_path):
    source = Path(__file__).resolve().parents[1] / "example" / "generate.py"
    spec = importlib.util.spec_from_file_location("demo", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.capture(tmp_path / "capture.pcap"), module.capture(
        tmp_path / "benign.pcap", False
    )


@pytest.fixture(autouse=True)
def private_user_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
