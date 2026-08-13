from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class TargetProfile(StrEnum):
    vulnerable = "demo-vulnerable"
    hardened = "demo-hardened"


class RuleResponse(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    description: str
    mitigation: str
    atlas_technique: str | None = None
    owasp_mapping: str


class FindingResponse(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: Severity
    passed: bool
    evidence: str
    remediation: str
    mapping: str
    latency_ms: int


class ScanCreate(BaseModel):
    target_name: str = Field(default="Demo RAG", min_length=2, max_length=120)
    target_profile: TargetProfile = TargetProfile.vulnerable
    categories: list[str] = Field(default_factory=list)


class ScanResponse(BaseModel):
    id: str
    target_name: str
    target_profile: str
    status: str
    score: float
    risk_level: str
    passed: int
    failed: int
    duration_ms: int
    findings: list[FindingResponse]
    created_at: datetime


class DashboardResponse(BaseModel):
    total_scans: int
    average_score: float
    high_risk_findings: int
    pass_rate: float
    latest_scan: ScanResponse | None
    category_risk: dict[str, int]

