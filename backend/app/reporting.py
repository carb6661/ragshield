import json

from app.schemas import ScanResponse
from app.services import render_markdown, render_sarif


def serialize_report(scan: ScanResponse, report_format: str) -> str:
    if report_format == "markdown":
        return render_markdown(scan)
    if report_format == "sarif":
        return json.dumps(render_sarif(scan), ensure_ascii=False, indent=2)
    if report_format == "json":
        return scan.model_dump_json(indent=2)
    raise ValueError(f"Unsupported report format: {report_format}")

