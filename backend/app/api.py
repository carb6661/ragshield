from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.core.rules import get_rules
from app.db import get_db
from app.schemas import DashboardResponse, RuleResponse, ScanCreate, ScanResponse
from app.services import create_scan, dashboard, get_scan, list_scans, render_markdown

router = APIRouter(prefix="/api/v1")


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
def start_scan(request: ScanCreate, db: Annotated[Session, Depends(get_db)]) -> ScanResponse:
    return create_scan(db, request)


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
def scan_report(scan_id: str, db: Annotated[Session, Depends(get_db)]) -> Response:
    scan = get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return Response(
        render_markdown(scan),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="ragshield-{scan_id}.md"'},
    )


@router.get("/dashboard", response_model=DashboardResponse)
def dashboard_stats(db: Annotated[Session, Depends(get_db)]) -> DashboardResponse:
    return dashboard(db)
