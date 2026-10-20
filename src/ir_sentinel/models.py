"""Persisted, versioned evidence records and typed tool results."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Indicator(Record):
    kind: Literal["ipv4", "ipv6", "domain", "md5", "sha1", "sha256"]
    value: str
    refs: list[str]
    first_seen: float | None = None
    last_seen: float | None = None


class Finding(Record):
    title: str
    confidence: Literal["low", "medium", "high"]
    refs: list[str]
    explanation: str


class EngineRun(Record):
    engine: str
    command: list[str]
    status: Literal["ok", "missing", "failed", "timeout", "limited"]
    exit_code: int | None = None
    output: str = ""
    error: str = ""


class Case(Record):
    schema_version: Literal[1] = 1
    id: str
    created_at: str
    kind: Literal["pcap", "file", "hash"]
    source_name: str
    source_path: str = ""
    sha256: str = ""
    hashes: dict[str, str] = Field(default_factory=dict)
    size: int | None = None
    observations: list[dict] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    engines: list[EngineRun] = Field(default_factory=list)
    intelligence: list[dict] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class CaseSummary(Record):
    case_id: str
    kind: str
    source_name: str
    sha256: str
    observations: int
    indicators: list[Indicator]
    findings: list[Finding]
    engine_status: dict[str, str]
    limitations: list[str]
    report_path: str


class Defense(Record):
    case_id: str
    platform: Literal["suricata", "zeek", "hashlist"]
    path: str
    content: str
    sha256: str
    evidence_refs: list[str]
    validation: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
