import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.scanner import run_scan
from app.core.targets import DemoTarget
from app.models import ScanRecord
from app.schemas import DashboardResponse, FindingResponse, ScanCreate, ScanResponse


def to_response(record: ScanRecord) -> ScanResponse:
    findings = [FindingResponse.model_validate(item) for item in json.loads(record.findings_json)]
    created_at = record.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return ScanResponse(
        id=record.id,
        target_name=record.target_name,
        target_profile=record.target_profile,
        status=record.status,
        score=record.score,
        risk_level=record.risk_level,
        passed=record.passed,
        failed=record.failed,
        duration_ms=record.duration_ms,
        findings=findings,
        created_at=created_at,
    )


def create_scan(db: Session, request: ScanCreate) -> ScanResponse:
    result = run_scan(DemoTarget(request.target_profile.value), request.categories)
    record = ScanRecord(
        id=str(uuid4()),
        target_name=request.target_name,
        target_profile=request.target_profile.value,
        score=result.score,
        risk_level=result.risk_level,
        passed=result.passed,
        failed=result.failed,
        duration_ms=result.duration_ms,
        findings_json=json.dumps(
            [finding.model_dump(mode="json") for finding in result.findings], ensure_ascii=False
        ),
        created_at=datetime.now(UTC),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return to_response(record)


def list_scans(db: Session, limit: int = 20) -> list[ScanResponse]:
    records = db.scalars(select(ScanRecord).order_by(desc(ScanRecord.created_at)).limit(limit))
    return [to_response(record) for record in records]


def get_scan(db: Session, scan_id: str) -> ScanResponse | None:
    record = db.get(ScanRecord, scan_id)
    return to_response(record) if record else None


def dashboard(db: Session) -> DashboardResponse:
    scans = list_scans(db, 100)
    total = int(db.scalar(select(func.count()).select_from(ScanRecord)) or 0)
    average = round(sum(scan.score for scan in scans) / len(scans), 1) if scans else 0.0
    findings = [finding for scan in scans for finding in scan.findings]
    failed = [finding for finding in findings if not finding.passed]
    high_risk = sum(f.severity.value in {"critical", "high"} for f in failed)
    pass_rate = round((len(findings) - len(failed)) / len(findings) * 100, 1) if findings else 0.0
    category_risk: dict[str, int] = {}
    for finding in failed:
        category_risk[finding.category] = category_risk.get(finding.category, 0) + 1
    return DashboardResponse(
        total_scans=total,
        average_score=average,
        high_risk_findings=high_risk,
        pass_rate=pass_rate,
        latest_scan=scans[0] if scans else None,
        category_risk=category_risk,
    )


def render_markdown(scan: ScanResponse) -> str:
    lines = [
        f"# RAGShield Security Report — {scan.target_name}",
        "",
        f"- Scan ID: `{scan.id}`",
        f"- Profile: `{scan.target_profile}`",
        f"- Security score: **{scan.score}/100**",
        f"- Risk level: **{scan.risk_level.upper()}**",
        f"- Controls: {scan.passed} passed / {scan.failed} failed",
        "",
        "## Findings",
        "",
    ]
    for finding in scan.findings:
        status = "PASS" if finding.passed else "FAIL"
        lines.extend(
            [
                f"### [{status}] {finding.rule_id} — {finding.title}",
                "",
                f"- Severity: {finding.severity.value}",
                f"- Category: {finding.category}",
                f"- Mapping: {finding.mapping}",
                f"- Evidence: {finding.evidence}",
                f"- Remediation: {finding.remediation}",
                "",
            ]
        )
    lines.extend(
        [
            "## Scope and responsible use",
            "",
            "This report was produced for an explicitly configured local demonstration target. "
            "Only assess systems you own or are authorized to test.",
        ]
    )
    return "\n".join(lines)

