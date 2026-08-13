import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.core.rules import get_rules
from app.core.targets import TargetConfigurationError, TargetRequestError
from app.db import get_db
from app.schemas import (
    CapabilitiesResponse,
    DashboardResponse,
    RuleResponse,
    ScanCreate,
    ScanResponse,
)
from app.services import (
    create_scan,
    dashboard,
    get_scan,
    list_scans,
    render_markdown,
    render_sarif,
)

router = APIRouter(prefix="/api/v1")
SettingsDep = Annotated[Settings, Depends(get_settings)]


@router.get("/rules", response_model=list[RuleResponse])
def rules() -> list[RuleResponse]:
    return [
        RuleResponse(
            id=rule.id,
            title=rule.title,
            category=rule.category,
            severity=rule.severity,
            description=rule.description,
            mitigation=rule.mitigation,
            atlas_technique=rule.atlas_technique,
            owasp_mapping=rule.owasp_mapping,
        )
        for rule in get_rules()
    ]


@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def start_scan(
    request: ScanCreate,
    db: Annotated[Session, Depends(get_db)],
    settings: SettingsDep,
) -> ScanResponse:
    try:
        return create_scan(db, request, settings)
    except TargetConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except TargetRequestError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/scans", response_model=list[ScanResponse])
def scans(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[ScanResponse]:
    return list_scans(db, limit)


@router.get("/scans/{scan_id}", response_model=ScanResponse)
def scan_detail(scan_id: str, db: Annotated[Session, Depends(get_db)]) -> ScanResponse:
    scan = get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans/{scan_id}/report")
def scan_report(
    scan_id: str,
    db: Annotated[Session, Depends(get_db)],
    report_format: Annotated[
        str, Query(alias="format", pattern="^(markdown|json|sarif)$")
    ] = "markdown",
) -> Response:
    scan = get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if report_format == "markdown":
        content = render_markdown(scan)
        media_type, extension = "text/markdown", "md"
    elif report_format == "sarif":
        content = json.dumps(render_sarif(scan), ensure_ascii=False, indent=2)
        media_type, extension = "application/sarif+json", "sarif"
    else:
        content = scan.model_dump_json(indent=2)
        media_type, extension = "application/json", "json"
    return Response(
        content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="ragshield-{scan_id}.{extension}"'
        },
    )


@router.get("/dashboard", response_model=DashboardResponse)
def dashboard_stats(db: Annotated[Session, Depends(get_db)]) -> DashboardResponse:
    return dashboard(db)


@router.get("/capabilities", response_model=CapabilitiesResponse)
def capabilities(settings: SettingsDep) -> CapabilitiesResponse:
    profiles = ["demo-vulnerable", "demo-hardened"]
    if settings.enable_network_targets:
        profiles.append("authorized-http")
    return CapabilitiesResponse(
        network_targets_enabled=settings.enable_network_targets,
        allowlisted_hosts=sorted(settings.http_target_hosts),
        supported_profiles=profiles,
        report_formats=["markdown", "json", "sarif"],
    )
