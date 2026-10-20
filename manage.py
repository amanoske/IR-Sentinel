#!/usr/bin/env python3
"""One-command setup and removal for the local Sentinel plugin (Python 3.11+)."""

import argparse
import getpass
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent
MARKETPLACE = "ir-sentinel"
SELECTOR = "sentinel@ir-sentinel"


def location(variable: str, default: str) -> Path:
    base = Path(os.environ.get(variable, str(Path.home() / default))).expanduser()
    if not base.is_absolute():
        raise ValueError(f"{variable} must be absolute")
    return base / "ir-sentinel"


def private(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("Sentinel's managed directory cannot be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("Sentinel's managed directory must be user-owned with permissions 700")
    return path


def save(path: Path, value: dict) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(args: list[str]) -> None:
    subprocess.run(args, check=True)


def configure_otx(config: Path, remove: bool = False) -> None:
    private(config)
    if remove:
        (config / "otx.json").unlink(missing_ok=True)
        print("OTX key removed. Local investigations still work.")
        return
    key = getpass.getpass("OTX API key (hidden; leave empty to cancel): ").strip()
    if not key:
        print("No changes made.")
        return
    if len(key) > 4096 or not key.isascii() or any(ord(c) < 33 for c in key):
        raise ValueError("The key contains invalid characters")
    save(config / "otx.json", {"key": key})
    print("OTX configured. Only explicit OTX lookups send indicators; files stay local.")


def install(root: Path, codex: str) -> None:
    private(root)
    interpreter = root / "runtime" / "bin" / "python"
    command([sys.executable, "-m", "venv", str(root / "runtime")])
    command([str(interpreter), "-m", "pip", "install", "--upgrade", str(REPOSITORY)])
    plugin = private(root / "plugin")
    for relative in (".codex-plugin", "skills"):
        shutil.copytree(REPOSITORY / "plugin" / relative, plugin / relative, dirs_exist_ok=True)
    save(
        plugin / ".mcp.json",
        {
            "mcpServers": {
                "sentinel": {"command": str(interpreter), "args": ["-m", "ir_sentinel.server"]}
            }
        },
    )
    catalog = root / ".agents" / "plugins"
    catalog.mkdir(parents=True, exist_ok=True)
    save(
        catalog / "marketplace.json",
        {
            "name": MARKETPLACE,
            "interface": {"displayName": "IR Sentinel"},
            "plugins": [
                {
                    "name": "sentinel",
                    "source": {"source": "local", "path": "./plugin"},
                    "policy": {"installation": "AVAILABLE", "authentication": "ON_USE"},
                    "category": "Developer tools",
                }
            ],
        },
    )
    marker = root / "installed.json"
    if marker.exists():
        command([codex, "plugin", "remove", SELECTOR])
        marker.unlink()
    command([codex, "plugin", "marketplace", "add", str(root)])
    command([codex, "plugin", "add", SELECTOR])
    save(marker, {"registered": True})
    print("Sentinel installed. Open a new local Codex chat and supply your evidence.")


def uninstall(root: Path, config: Path, state: Path, codex: str | None, purge: bool) -> None:
    if root.exists():
        private(root)
        if (root / "installed.json").exists():
            if not codex:
                raise ValueError("Codex CLI is needed to remove the registered plugin")
            command([codex, "plugin", "remove", SELECTOR])
            (root / "installed.json").unlink()
            command([codex, "plugin", "marketplace", "remove", MARKETPLACE])
        shutil.rmtree(root)
    if config.exists():
        private(config)
        (config / "otx.json").unlink(missing_ok=True)
        if not any(config.iterdir()):
            config.rmdir()
    if purge and state.exists():
        private(state)
        shutil.rmtree(state)
    print("Sentinel removed, including its saved OTX key.")
    print("Generated reports removed." if purge else f"Generated reports retained at {state}.")
    print("Your supplied evidence was not copied, modified or deleted.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("install", help="Install or update Sentinel for Codex CLI and Desktop")
    otx = actions.add_parser("otx", help="Privately save or remove an optional OTX API key")
    otx.add_argument("--remove", action="store_true")
    actions.add_parser("doctor", help="Check the installation and locally available engines")
    remove = actions.add_parser("uninstall", help="Remove Sentinel and its stored key")
    remove.add_argument(
        "--purge", action="store_true", help="Also delete generated case reports"
    )
    args = parser.parse_args()
    if os.name != "posix" or sys.version_info < (3, 11):
        parser.error("Sentinel currently requires Linux/macOS and Python 3.11 or newer")
    root = location("XDG_DATA_HOME", ".local/share")
    config = location("XDG_CONFIG_HOME", ".config")
    state = location("XDG_STATE_HOME", ".local/state")
    codex = shutil.which("codex")
    try:
        if args.action == "install":
            if not codex:
                raise ValueError(
                    "Install Codex CLI first, then rerun this command (see README)"
                )
            install(root, codex)
        elif args.action == "otx":
            configure_otx(config, args.remove)
        elif args.action == "doctor":
            interpreter = root / "runtime" / "bin" / "python"
            if not interpreter.is_file():
                raise ValueError("Sentinel is not installed. Run python3 manage.py install")
            command(
                [
                    str(interpreter),
                    "-c",
                    "import json; "
                    "from ir_sentinel.server import sentinel_status; "
                    "print(json.dumps(sentinel_status(), indent=2))",
                ]
            )
        else:
            uninstall(root, config, state, codex, args.purge)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Sentinel setup failed: {exc}\n")


if __name__ == "__main__":
    main()
