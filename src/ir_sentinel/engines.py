"""Offline native-engine adapters. Commands never use a shell or live interfaces."""

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

from .models import EngineRun
from .storage import private_dir

OUTPUT_LIMIT = 16 * 1024 * 1024


def discover() -> dict[str, str | None]:
    result = {}
    for name in ("tshark", "suricata", "zeek"):
        alternatives = ("zeek", "bro") if name == "zeek" else (name,)
        result[name] = next(
            (found for candidate in alternatives if (found := shutil.which(candidate))), None
        )
        if not result[name]:
            for base in ("/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/opt/zeek/bin"):
                for candidate in alternatives:
                    found = Path(base) / candidate
                    if found.is_file() and os.access(found, os.X_OK):
                        result[name] = str(found)
                        break
                if result[name]:
                    break
    return result


def execute(
    engine: str, arguments: list[str], directory: Path, timeout: float = 60
) -> EngineRun:
    executable = discover().get(engine)
    if not executable:
        return EngineRun(
            engine=engine,
            command=arguments,
            status="missing",
            error=f"{engine} is not installed; this analysis was skipped",
        )
    private_dir(directory)
    command = [executable, *arguments]
    result = EngineRun(engine=engine, command=command, status="ok")
    with (
        (directory / "stdout.txt").open("wb+") as out,
        (directory / "stderr.txt").open("wb+") as err,
    ):
        try:
            process = subprocess.Popen(
                command,
                cwd=directory,
                stdout=out,
                stderr=err,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                env={"PATH": os.defpath, "LC_ALL": "C"},
            )
        except OSError as exc:
            return result.model_copy(update={"status": "failed", "error": str(exc)})
        started = time.monotonic()
        while process.poll() is None:
            size = sum(p.stat().st_size for p in directory.rglob("*") if p.is_file())
            if size > OUTPUT_LIMIT:
                result.status = "limited"
            elif time.monotonic() - started > timeout:
                result.status = "timeout"
            if result.status != "ok":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                break
            time.sleep(0.05)
        result.exit_code = process.returncode
        if result.status == "ok" and process.returncode:
            result.status = "failed"
        if sum(p.stat().st_size for p in directory.rglob("*") if p.is_file()) > OUTPUT_LIMIT:
            result.status = "limited"
        out.seek(0)
        err.seek(0)
        result.output = out.read(OUTPUT_LIMIT).decode("utf-8", "replace")
        result.error = err.read(8192).decode("utf-8", "replace")
    return result


def suricata_config(path: Path) -> Path:
    # A self-contained offline config avoids changing or relying on system rule paths.
    (path / "classification.config").write_text(
        "# No classifications required by generated rules\n"
    )
    (path / "reference.config").write_text("# No external rule references\n")
    config = path / "suricata.yaml"
    config.write_text("""%YAML 1.1
---
classification-file: classification.config
reference-config-file: reference.config
vars:
  address-groups:
    HOME_NET: any
    EXTERNAL_NET: any
  port-groups:
    HTTP_PORTS: any
stream:
  checksum-validation: no
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types: [alert, http, dns, tls]
logging:
  default-log-level: warning
  outputs:
    - console:
        enabled: yes
app-layer:
  protocols:
    http:
      enabled: yes
""")
    return config
