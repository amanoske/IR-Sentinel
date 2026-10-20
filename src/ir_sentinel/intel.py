"""Read-only OTX correlation, with explicit disclosure and no actor verdicts."""

import json
import os
import stat
from datetime import UTC, datetime
from urllib.parse import quote

import httpx

from .investigation import normalize_indicator, write_report
from .models import Indicator
from .storage import Store, read_json, user_path, write_json

API = "https://otx.alienvault.com/api/v1/indicators"
SLUGS = {
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "domain": "domain",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
}


def configured_key() -> str:
    path = user_path("config") / "otx.json"
    if not path.exists():
        return ""
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise PermissionError("OTX configuration must be a private user-owned regular file")
    value = read_json(path, 8192).get("key", "")
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.strip()
        or len(value) > 4096
    ):
        raise ValueError("Invalid OTX key configuration; rerun OTX setup")
    return value


def date(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.replace(tzinfo=UTC) if result.tzinfo is None else result.astimezone(UTC)
    except ValueError:
        return None


def association(pulse: dict, indicator: Indicator) -> dict:
    published = date(pulse.get("created"))
    relation = "unknown"
    if published and indicator.last_seen is not None:
        relation = (
            "published_after_observation"
            if published.timestamp() > indicator.last_seen
            else "published_by_end_of_observation"
        )
    return {
        "pulse_id": str(pulse.get("id", ""))[:128],
        "name": str(pulse.get("name", ""))[:256],
        "reported_adversary": str(pulse.get("adversary") or "unknown")[:256],
        "published": published.isoformat() if published else None,
        "publication_timing": relation,
        "confidence": "low",
    }


def lookup(client: httpx.Client, indicator: Indicator) -> dict:
    value, public = normalize_indicator(indicator.kind, indicator.value)
    result = {
        "kind": indicator.kind,
        "indicator": value,
        "evidence_refs": indicator.refs,
        "first_seen": indicator.first_seen,
        "last_seen": indicator.last_seen,
        "status": "skipped",
        "actor_attribution": "unknown",
        "associations": [],
    }
    if not public:
        result["reason"] = "Private, reserved or internal indicator: not disclosed to OTX"
        return result
    url = f"{API}/{SLUGS[indicator.kind]}/{quote(value, safe='')}/general"
    result.update(source_url=url, retrieved_at=datetime.now(UTC).isoformat())
    try:
        with client.stream("GET", url) as response:
            result["http_status"] = response.status_code
            response.raise_for_status()
            raw = bytearray()
            for block in response.iter_bytes():
                raw.extend(block)
                if len(raw) > 1024 * 1024:
                    raise ValueError("Response too large")
            payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("Expected JSON object")
        pulse_info = payload.get("pulse_info")
        if not isinstance(pulse_info, dict) or not isinstance(pulse_info.get("pulses"), list):
            raise ValueError("Missing or malformed OTX association data")
        pulses = pulse_info["pulses"]
        count = pulse_info.get("count", len(pulses))
        if not isinstance(count, int) or count < 0:
            raise ValueError("Malformed OTX association count")
        if any(not isinstance(pulse, dict) for pulse in pulses):
            raise ValueError("Malformed OTX pulse")
        result.update(
            status="ok",
            reported_pulse_count=count,
            associations=[association(p, indicator) for p in pulses[:10]],
            associations_truncated=count > min(len(pulses), 10),
            reputation=str(payload.get("reputation", "not provided"))[:128],
        )
    except httpx.HTTPStatusError:
        code = result["http_status"]
        result.update(
            status="error",
            reason={
                401: "OTX key rejected",
                403: "OTX access denied",
                404: "OTX has no resource; this is not a clean verdict",
                429: "OTX rate limit reached; retry later",
            }.get(code, "OTX HTTP failure"),
        )
    except (httpx.HTTPError, ValueError, UnicodeError):
        result.update(
            status="error", reason="OTX unavailable or response invalid; inconclusive"
        )
    return result


def enrich(
    store: Store,
    case_id: str,
    values: list[str] | None = None,
    client: httpx.Client | None = None,
) -> dict:
    case = store.load(case_id)
    indicators = case.indicators
    if values is not None:
        if not values or len(values) > 10:
            raise ValueError("Select between 1 and 10 observed indicator values")
        if set(values) - {i.value for i in indicators}:
            raise ValueError("Only indicators observed in this case can be enriched")
        indicators = [i for i in indicators if i.value in values]
    indicators = indicators[:10]
    key = configured_key()
    if not key:
        return {
            "status": "unconfigured",
            "instructions": "Run python3 manage.py otx once; "
            "enter your key privately at the terminal prompt",
        }
    if client is None:
        with httpx.Client(
            headers={"X-OTX-API-KEY": key}, timeout=10, follow_redirects=False
        ) as own:
            records = [lookup(own, indicator) for indicator in indicators]
    else:
        records = [lookup(client, indicator) for indicator in indicators]
    case.intelligence = records
    limitations = [
        "OTX Pulse links are provider-reported associations, not proof of malicious activity "
        "or actor involvement; attribution remains unknown",
        "Publication dates are not activity start/end dates; timing is compared only with "
        "captured packet times, never file modification times",
        "At most 10 indicators and 10 Pulse summaries per indicator per request; no match "
        "and provider errors are not benign verdicts",
    ]
    for limitation in limitations:
        if limitation not in case.limitations:
            case.limitations.append(limitation)
    store.save(case)
    write_report(store, case)
    write_json(store.directory(case.id) / "intelligence.json", {"records": records})
    return {"case_id": case.id, "records": records, "limitations": limitations}
