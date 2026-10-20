import importlib.util
import json
import stat
from pathlib import Path

import pytest


@pytest.fixture
def setup_module():
    spec = importlib.util.spec_from_file_location(
        "sentinel_manage", Path(__file__).resolve().parents[1] / "manage.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_installer_builds_plugin_with_absolute_runtime(tmp_path, monkeypatch, setup_module):
    commands = []
    monkeypatch.setattr(setup_module, "command", commands.append)
    root = tmp_path / "directory with spaces"
    setup_module.install(root, "/usr/bin/codex")
    server = json.loads((root / "plugin/.mcp.json").read_text())["mcpServers"]["sentinel"]
    assert server["command"] == str(root / "runtime/bin/python")
    assert server["args"] == ["-m", "ir_sentinel.server"]
    assert commands[-1] == ["/usr/bin/codex", "plugin", "add", "sentinel@ir-sentinel"]
    catalog = json.loads((root / ".agents/plugins/marketplace.json").read_text())
    assert (root / catalog["plugins"][0]["source"]["path"]).is_dir()
    config = tmp_path / "config"
    monkeypatch.setattr(setup_module.getpass, "getpass", lambda prompt: "fake-test-key")
    setup_module.configure_otx(config)
    assert stat.S_IMODE((config / "otx.json").stat().st_mode) == 0o600
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "report").write_text("Retain this report by default")
    evidence = tmp_path / "user-evidence"
    evidence.write_text("Do not remove")
    setup_module.uninstall(root, config, state, "/usr/bin/codex", False)
    assert not root.exists() and not config.exists()
    assert (state / "report").exists() and evidence.exists()
    setup_module.uninstall(root, config, state, None, True)
    assert not state.exists() and evidence.exists()


def test_setup_rejects_symlink_storage(tmp_path, setup_module):
    target = tmp_path / "unrelated"
    target.mkdir()
    link = tmp_path / "sentinel"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        setup_module.private(link)
