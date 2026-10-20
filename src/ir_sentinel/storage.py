"""Private per-user storage and in-place inspection of explicitly supplied evidence."""

import hashlib
import json
import os
import re
import stat
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .models import Case

MAX_EVIDENCE = 128 * 1024 * 1024
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}


def user_path(kind: str) -> Path:
    roots = {
        "config": ("XDG_CONFIG_HOME", ".config"),
        "state": ("XDG_STATE_HOME", ".local/state"),
    }
    variable, fallback = roots[kind]
    base = Path(os.environ.get(variable, str(Path.home() / fallback))).expanduser()
    if not base.is_absolute():
        raise ValueError(f"{variable} must be absolute")
    return base / "ir-sentinel"


def private_dir(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("Sentinel storage cannot be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError("Sentinel storage must be owned by you with permissions 700")
    return path


def write_json(path: Path, value: dict) -> None:
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path: Path, maximum: int = 32 * 1024 * 1024) -> dict:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("Invalid or oversized Sentinel record")
        return json.load(stream)


class Store:
    def __init__(self, root: Path | None = None):
        self.root = private_dir((root or user_path("state")).absolute())
        self.cases = private_dir(self.root / "cases")

    def directory(self, case_id: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{32}", case_id):
            raise ValueError("Invalid case ID")
        path = self.cases / case_id
        if path.is_symlink() or not path.is_dir():
            raise ValueError("Unknown case ID")
        return path

    def create(self, source_name: str, kind: str) -> Case:
        case_id = uuid.uuid4().hex
        private_dir(self.cases / case_id)
        return Case(
            id=case_id,
            created_at=datetime.now(UTC).isoformat(),
            kind=kind,
            source_name=source_name,
        )

    def save(self, case: Case) -> None:
        write_json(self.directory(case.id) / "case.json", case.model_dump())

    def load(self, case_id: str) -> Case:
        return Case.model_validate(read_json(self.directory(case_id) / "case.json"))

    def inspect(self, source: str) -> tuple[Case, Path]:
        path, hashes, size, magic = fingerprint(source)
        case = self.create(path.name, "pcap" if magic in PCAP_MAGIC else "file")
        case.source_path = str(path)
        case.hashes = hashes
        case.sha256, case.size = hashes["sha256"], size
        return case, path


def fingerprint(source: str) -> tuple[Path, dict[str, str], int, bytes]:
    """Read the supplied file in place. Never copy or modify it."""
    path = Path(source).expanduser().absolute()
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_EVIDENCE:
            raise ValueError("Supply a regular file of at most 128 MiB")
        magic = stream.read(4)
        stream.seek(0)
        hashes = {
            name: hashlib.new(name, usedforsecurity=False) for name in ("md5", "sha1", "sha256")
        }
        size = 0
        while block := stream.read(1024 * 1024):
            size += len(block)
            if size > MAX_EVIDENCE:
                raise ValueError("Evidence exceeded 128 MiB while reading")
            for hasher in hashes.values():
                hasher.update(block)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("Evidence changed while reading; supply a stable file")
    return path, {name: hasher.hexdigest() for name, hasher in hashes.items()}, size, magic


def verify_source(case: Case) -> Path:
    try:
        path, hashes, _, _ = fingerprint(case.source_path)
    except OSError:
        raise ValueError(
            "Evidence is unavailable; supply it again to start a new investigation"
        ) from None
    if hashes["sha256"] != case.sha256:
        raise ValueError("Evidence changed; supply it again to start a new investigation")
    return path
