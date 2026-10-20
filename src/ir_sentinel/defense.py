"""Generate observation-specific candidates and validate through offline replay."""

import hashlib
import json
import uuid
from pathlib import Path
from typing import Literal

from .engines import execute, suricata_config
from .models import Defense
from .storage import (
    PCAP_MAGIC,
    Store,
    fingerprint,
    private_dir,
    read_json,
    verify_source,
    write_json,
)

Platform = Literal["suricata", "zeek", "hashlist"]


def build(store: Store, case_id: str, platform: Platform) -> Defense:
    case = store.load(case_id)
    if platform not in ("suricata", "zeek", "hashlist"):
        raise ValueError("Unsupported defense platform")
    if platform == "hashlist":
        if case.kind == "pcap":
            raise ValueError("Hash watchlists are for file/hash investigations")
        content = (
            json.dumps(
                {"hashes": case.hashes, "action": "review", "case_id": case.id}, indent=2
            )
            + "\n"
        )
        refs, extension = [case.observations[0]["ref"]], "json"
    else:
        requests = [
            o
            for o in case.observations
            if o.get("http.request.uri") and any(o["ref"] in f.refs for f in case.findings)
        ]
        if case.kind != "pcap" or not requests:
            raise ValueError("A suspicious HTTP request observation is required for this rule")
        request = requests[0]
        uri = request["http.request.uri"]
        if len(uri.encode()) > 512:
            raise ValueError("Request URI too long for a narrow generated rule")
        refs = [request["ref"]]
        if platform == "suricata":
            # Hex content cannot inject Suricata rule syntax.
            encoded = " ".join(f"{byte:02x}" for byte in uri.encode())
            sid = 1000000 + int(case.id[:6], 16) % 9000000
            content = (
                f'alert http any any -> any any (msg:"Sentinel observed URI"; '
                f'flow:established,to_server; http.uri.raw; content:"|{encoded}|"; '
                f"sid:{sid}; rev:1;)\n"
            )
            extension = "rules"
        else:
            literal = '"' + "".join(f"\\x{byte:02x}" for byte in uri.encode()) + '"'
            content = f"""@load base/frameworks/notice
module Sentinel;
export
{{
  redef enum Notice::Type +=
  {{
    Observed_URI
  }};
}}
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{{
  if (original_URI == {literal})
  {{
    NOTICE([$note=Observed_URI, $msg="Sentinel observed URI", $conn=c]);
  }}
}}
"""
            extension = "zeek"
    directory = private_dir(store.directory(case.id) / "defenses")
    path = directory / f"{uuid.uuid4().hex}.{extension}"
    path.write_text(content)
    result = Defense(
        case_id=case.id,
        platform=platform,
        path=str(path),
        content=content,
        sha256=hashlib.sha256(content.encode()).hexdigest(),
        evidence_refs=refs,
        limitations=[
            "Candidate matches observed evidence, not an actor or campaign",
            "Review false positives and local policy before deployment",
            "No services, firewall rules or endpoint state were changed",
        ],
    )
    write_json(path.with_suffix(".record.json"), result.model_dump())
    return result


def replay(
    store: Store, case_id: str, artifact_id: str, benign_path: str | None = None
) -> Defense:
    import re

    if not re.fullmatch(r"[0-9a-f]{32}", artifact_id):
        raise ValueError("Invalid artifact ID (use the generated filename stem)")
    directory = store.directory(case_id) / "defenses"
    result = Defense.model_validate(read_json(directory / f"{artifact_id}.record.json"))
    artifact = Path(result.path)
    if artifact.parent != directory or artifact.is_symlink():
        raise ValueError("Invalid artifact location")
    if hashlib.sha256(artifact.read_bytes()).hexdigest() != result.sha256:
        raise ValueError("Artifact changed; regenerate before validation")
    if result.platform == "hashlist":
        result.validation = {
            "status": "format_checked",
            "hashes": json.loads(result.content)["hashes"],
        }
    else:
        case = store.load(case_id)
        sources = {"case": verify_source(case)}
        expected = {"case": case.sha256}
        if benign_path:
            benign, hashes, _, magic = fingerprint(benign_path)
            if magic not in PCAP_MAGIC:
                raise ValueError("Benign replay requires PCAP/PCAPNG evidence")
            sources["benign"] = benign
            expected["benign"] = hashes["sha256"]
        runs = {}
        for label, source in sources.items():
            folder = private_dir(directory / f"replay-{uuid.uuid4().hex}")
            if result.platform == "suricata":
                config = suricata_config(folder)
                syntax = execute(
                    "suricata",
                    ["-T", "-c", str(config), "-S", str(artifact), "-l", str(folder)],
                    folder,
                )
                args = [
                    "-c",
                    str(config),
                    "-S",
                    str(artifact),
                    "-r",
                    str(source),
                    "-l",
                    str(folder),
                    "--runmode",
                    "single",
                    "-k",
                    "none",
                ]
                event_file = folder / "eve.json"
            else:
                syntax = execute("zeek", ["-a", str(artifact)], folder)
                args = ["-C", "-r", str(source), str(artifact), "LogAscii::use_json=T"]
                event_file = folder / "notice.log"
            run = execute(result.platform, args, folder) if syntax.status == "ok" else syntax
            if fingerprint(str(source))[1]["sha256"] != expected[label]:
                raise ValueError("Evidence changed during replay; results cannot be validated")
            matches = None
            if run.status == "ok":
                matches = 0
                if event_file.exists():
                    for line in event_file.read_text().splitlines():
                        data = json.loads(line)
                        if (
                            data.get("event_type") == "alert"
                            or data.get("note") == "Sentinel::Observed_URI"
                        ):
                            matches += 1
            runs[label] = {
                "syntax": syntax.model_dump(exclude={"output"}),
                "replay": run.model_dump(exclude={"output"}),
                "matches": matches,
            }
        valid = (
            runs["case"]["matches"] is not None
            and runs["case"]["matches"] > 0
            and "benign" in runs
            and runs["benign"]["matches"] == 0
        )
        result.validation = {
            "status": "validated_on_supplied_samples" if valid else "incomplete",
            "runs": runs,
        }
        if not benign_path:
            result.limitations.append("No benign comparison supplied; false positives untested")
    write_json(directory / f"{artifact_id}.record.json", result.model_dump())
    return result
