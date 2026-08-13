from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, SecretStr, model_validator


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class TargetProfile(StrEnum):
    vulnerable = "demo-vulnerable"
    hardened = "demo-hardened"
    authorized_http = "authorized-http"


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
    endpoint_url: str | None = Field(default=None, max_length=2048)
    response_field: str = Field(default="answer", pattern=r"^[A-Za-z0-9_.-]{1,80}$")
    bearer_token: SecretStr | None = Field(default=None, exclude=True)

    @model_validator(mode="after")
    def validate_http_target(self):
        if self.target_profile == TargetProfile.authorized_http and not self.endpoint_url:
            raise ValueError("endpoint_url is required for an authorized HTTP target")
        if self.target_profile != TargetProfile.authorized_http and self.endpoint_url:
            raise ValueError("endpoint_url is only valid for an authorized HTTP target")
        return self


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


class CapabilitiesResponse(BaseModel):
    network_targets_enabled: bool
    allowlisted_hosts: list[str]
    supported_profiles: list[str]
    report_formats: list[str]
