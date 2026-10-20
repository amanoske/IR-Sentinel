"""Evidence normalization; findings describe observations rather than actor verdicts."""

import csv
import io
import ipaddress
import json
import math
import re
from pathlib import Path
from urllib.parse import unquote

from .engines import execute, suricata_config
from .models import Case, CaseSummary, Finding, Indicator
from .storage import Store, private_dir, verify_source

PACKET_LIMIT = 10000
FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "_ws.col.Protocol",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
    "http.request.method",
    "http.request.uri",
    "http.response.code",
    "tcp.stream",
]


def normalize_indicator(kind: str, value: str) -> tuple[str, bool]:
    if kind in ("md5", "sha1", "sha256"):
        size = {"md5": 32, "sha1": 40, "sha256": 64}[kind]
        if not re.fullmatch(r"[a-fA-F0-9]{" + str(size) + "}", value):
            raise ValueError("Invalid file hash")
        return value.lower(), True
    if kind in ("ipv4", "ipv6"):
        address = ipaddress.ip_address(value)
        if address.version != (4 if kind == "ipv4" else 6) or "%" in value:
            raise ValueError("Invalid IP indicator")
        return str(address), address.is_global and not address.is_multicast
    if kind != "domain":
        raise ValueError("Unsupported indicator type")
    value = value.rstrip(".").encode("idna").decode().lower()
    if len(value) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")
    ):
        raise ValueError("Invalid domain")
    # IP literals must be evaluated by the address policy, never the domain policy.
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("An IP literal is not a domain")
    suffixes = ("local", "internal", "localhost", "invalid", "test", "example", "lan", "arpa")
    return value, "." in value and not any(
        value == s or value.endswith("." + s) for s in suffixes
    )


def add_indicator(
    case: Case, kind: str, value: str, ref: str, timestamp: float | None = None
) -> None:
    try:
        value, _ = normalize_indicator(kind, value)
    except (ValueError, UnicodeError):
        return
    previous = next((i for i in case.indicators if (i.kind, i.value) == (kind, value)), None)
    if previous:
        if ref not in previous.refs and len(previous.refs) < 20:
            previous.refs.append(ref)
        if timestamp is not None:
            previous.first_seen = min(
                previous.first_seen if previous.first_seen is not None else timestamp, timestamp
            )
            previous.last_seen = max(
                previous.last_seen if previous.last_seen is not None else timestamp, timestamp
            )
    elif len(case.indicators) < 200:
        case.indicators.append(
            Indicator(
                kind=kind, value=value, refs=[ref], first_seen=timestamp, last_seen=timestamp
            )
        )


def parse_packets(case: Case, text: str) -> None:
    for row in csv.DictReader(io.StringIO(text), delimiter="\t", quotechar='"'):
        number = int(row["frame.number"])
        timestamp = float(row["frame.time_epoch"])
        if not math.isfinite(timestamp):
            raise ValueError("Invalid packet time")
        ref = f"packet:{number}"
        observation = {"ref": ref, **{k: (v or "")[:1024] for k, v in row.items() if k}}
        case.observations.append(observation)
        for field, kind in (
            ("ip.src", "ipv4"),
            ("ip.dst", "ipv4"),
            ("ipv6.src", "ipv6"),
            ("ipv6.dst", "ipv6"),
            ("dns.qry.name", "domain"),
            ("tls.handshake.extensions_server_name", "domain"),
        ):
            if row.get(field):
                add_indicator(case, kind, row[field], ref, timestamp)
        uri = unquote(unquote(row.get("http.request.uri") or ""))
        if re.search(r"(?:\.\./){2}|\$\{jndi:|\bunion\s+select\b", uri, re.I):
            if len(case.findings) < 100:
                case.findings.append(
                    Finding(
                        title="Suspicious HTTP request syntax",
                        confidence="medium",
                        refs=[ref],
                        explanation="Request contains traversal, JNDI, or SQL-like syntax. "
                        "This can indicate an attempt; it does not establish exploitation.",
                    )
                )
        if len(case.observations) >= PACKET_LIMIT:
            case.limitations.append("Packet limit reached; remaining traffic was not examined")
            break


def read_events(case: Case, path: Path, engine: str) -> None:
    if not path.is_file():
        return
    with path.open(errors="replace") as stream:
        for index, line in enumerate(stream):
            if index >= 500:
                case.limitations.append(f"{engine} events capped at 500 per log")
                break
            if len(line) > 16384:
                case.limitations.append(f"Oversized {engine} event omitted")
                continue
            try:
                data = json.loads(line)
            except ValueError:
                case.limitations.append(f"Invalid {engine} JSON event omitted")
                continue
            if not isinstance(data, dict):
                continue
            ref = f"{engine}:{path.name}:{index + 1}"
            case.observations.append({"ref": ref, "event": data})
            if engine == "suricata" and data.get("event_type") == "alert":
                case.findings.append(
                    Finding(
                        title="IDS alert",
                        confidence="low",
                        refs=[ref],
                        explanation="Suricata matched a rule. Validate its context before "
                        "inferring compromise: "
                        + str(data.get("alert", {}).get("signature", "")),
                    )
                )


def analyze_capture(store: Store, case: Case, source: Path) -> None:
    folder = store.directory(case.id)
    args = [
        "-n",
        "-r",
        str(source),
        "-c",
        str(PACKET_LIMIT),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in FIELDS:
        args.extend(["-e", field])
    result = execute("tshark", args, folder / "tshark")
    if result.status == "ok":
        try:
            parse_packets(case, result.output)
        except (ValueError, KeyError, csv.Error):
            case.limitations.append(
                "Packet normalization failed; packet results are incomplete"
            )
    else:
        case.limitations.append("TShark unavailable or failed: no complete packet assessment")
    case.engines.append(result.model_copy(update={"output": ""}))
    suri = private_dir(folder / "suricata")
    config = suricata_config(suri)
    empty_rules = suri / "baseline.rules"
    empty_rules.write_text(
        "# Protocol metadata only; no third-party signature set is bundled.\n"
    )
    result = execute(
        "suricata",
        [
            "-c",
            str(config),
            "-S",
            str(empty_rules),
            "-r",
            str(source),
            "-l",
            str(suri),
            "--runmode",
            "single",
            "-k",
            "none",
        ],
        suri,
    )
    case.engines.append(result.model_copy(update={"output": ""}))
    if result.status == "ok":
        read_events(case, suri / "eve.json", "suricata")
    result = execute("zeek", ["-C", "-r", str(source), "LogAscii::use_json=T"], folder / "zeek")
    case.engines.append(result.model_copy(update={"output": ""}))
    if result.status == "ok":
        for name in ("conn.log", "dns.log", "http.log", "notice.log"):
            read_events(case, folder / "zeek" / name, "zeek")
    case.limitations.extend(
        [
            "Encryption, loss and truncation limit visibility; no live capture occurs",
            "Suricata baseline collects metadata; no threat signature feed is bundled",
            "First field occurrence only; fields capped at 1024 characters; 200 unique IOCs "
            "and 20 references per IOC retained",
            "No finding does not establish benign traffic; actor identity remains unknown",
        ]
    )


def analyze_file(case: Case, source: Path) -> None:
    with source.open("rb") as stream:
        sample = stream.read(1024 * 1024)
    magic = (
        "PE-like"
        if sample.startswith(b"MZ")
        else "ELF"
        if sample.startswith(b"\x7fELF")
        else "ZIP-like"
        if sample.startswith(b"PK\x03\x04")
        else "unidentified"
    )
    case.observations.append(
        {"ref": "file:metadata", "format_hint": magic, "size": case.size, "hashes": case.hashes}
    )
    for match in list(re.finditer(rb"[\x20-\x7e]{8,256}", sample))[:100]:
        case.observations.append(
            {"ref": f"file:offset:{match.start()}", "text": match.group().decode("ascii")}
        )
    add_indicator(case, "sha256", case.sha256, "file:metadata")
    case.limitations.extend(
        [
            "Static metadata and bounded strings only: files are never executed or uploaded",
            "Format hints and embedded strings do not establish malware or endpoint execution",
            "Strings sampled from first 1 MiB, at most 100 strings of 256 characters",
            "File modification time is not treated as an incident timestamp",
        ]
    )


def write_report(store: Store, case: Case) -> Path:
    path = store.directory(case.id) / "report.md"
    # JSON quoting keeps evidence text visibly distinct from narrative instructions.
    lines = [
        "# Sentinel investigation",
        f"Case: `{case.id}`",
        f"Kind: {case.kind}",
        f"Source: {json.dumps(case.source_name)}",
        f"SHA-256: `{case.sha256}`",
        "## Observations",
        f"{len(case.observations)} retained evidence records.",
        "Use read_evidence to inspect referenced records.",
        "## Findings",
    ]
    for finding in case.findings:
        lines.append(
            f"- {json.dumps(finding.title)} ({finding.confidence}): "
            f"{json.dumps(finding.explanation)}; refs: {', '.join(finding.refs)}"
        )
    if not case.findings:
        lines.append("No heuristic finding. This is not a benign verdict.")
    lines.extend(["## Intelligence", "Actor attribution: unknown."])
    for record in case.intelligence:
        lines.append(
            "```json\n" + json.dumps(record, indent=2).replace("`", "\\u0060") + "\n```"
        )
    lines.append("## Limitations")
    lines.extend("- " + text for text in case.limitations)
    lines.append("## Suggested response")
    lines.extend(
        [
            "- Preserve original evidence and obtain endpoint/process context.",
            "- Compare suspicious observations against authorized activity and timelines.",
            "- Review generated detections and test benign traffic before deployment.",
            "- For corroborated compromise, use your approved containment process; "
            "Sentinel does not isolate hosts, block traffic, or change services.",
        ]
    )
    path.write_text("\n\n".join(lines) + "\n")
    return path


def summarize(store: Store, case: Case) -> CaseSummary:
    return CaseSummary(
        case_id=case.id,
        kind=case.kind,
        source_name=case.source_name,
        sha256=case.sha256,
        observations=len(case.observations),
        indicators=case.indicators,
        findings=case.findings,
        engine_status={run.engine: run.status for run in case.engines},
        limitations=case.limitations,
        report_path=str(write_report(store, case)),
    )


def investigate(
    store: Store, path: str | None = None, hash_value: str | None = None
) -> CaseSummary:
    if bool(path) == bool(hash_value):
        raise ValueError("Supply either an accessible evidence path or a file hash")
    if hash_value:
        kind = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(hash_value.strip()), "")
        value, _ = normalize_indicator(kind, hash_value.strip())
        case = store.create("user-supplied hash", "hash")
        case.hashes[kind] = value
        case.sha256 = value if kind == "sha256" else ""
        case.observations.append({"ref": "hash:input", "kind": kind, "value": value})
        add_indicator(case, kind, value, "hash:input")
        case.limitations.append(
            "User-supplied hash; no file contents or incident time available"
        )
    else:
        case, source = store.inspect(path)
        if case.kind == "pcap":
            analyze_capture(store, case, source)
        else:
            analyze_file(case, source)
        verify_source(case)
    store.save(case)
    return summarize(store, case)
