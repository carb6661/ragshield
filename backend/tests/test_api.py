def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_scan_lifecycle_and_report(client):
    created = client.post(
        "/api/v1/scans",
        json={"target_name": "Secure demo", "target_profile": "demo-hardened"},
    )
    assert created.status_code == 201
    payload = created.json()
    assert payload["score"] == 100
    assert payload["failed"] == 0

    scan_id = payload["id"]
    detail = client.get(f"/api/v1/scans/{scan_id}")
    assert detail.status_code == 200
    assert detail.json()["target_name"] == "Secure demo"

    report = client.get(f"/api/v1/scans/{scan_id}/report")
    assert report.status_code == 200
    assert "RAGShield Security Report" in report.text


def test_dashboard_aggregates_findings(client):
    client.post(
        "/api/v1/scans", json={"target_name": "Lab A", "target_profile": "demo-vulnerable"}
    )
    client.post(
        "/api/v1/scans", json={"target_name": "Lab B", "target_profile": "demo-hardened"}
    )
    response = client.get("/api/v1/dashboard")
    assert response.status_code == 200
    payload = response.json()
    assert payload["total_scans"] == 2
    assert payload["average_score"] == 50
    assert payload["high_risk_findings"] == 5


def test_unknown_scan_returns_404(client):
    assert client.get("/api/v1/scans/not-found").status_code == 404
