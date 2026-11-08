def sample_payload(**overrides):
    payload = {
        "event_type": "authentication",
        "source": "linux-server",
        "source_ip": "192.168.1.50",
        "username": "admin",
        "outcome": "failure",
        "occurred_at": "2026-11-08T12:00:00Z",
        "details": {
            "method": "ssh",
            "attempt": 1,
        },
    }
    payload.update(overrides)
    return payload


def test_root_endpoint(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["name"] == "SENTINEL AI"
    assert response.json()["status"] == "running"


def test_health_endpoint(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["database"] == "connected"


def test_ingest_security_event(client):
    response = client.post(
        "/api/v1/events",
        json=sample_payload(),
    )

    assert response.status_code == 201

    data = response.json()
    assert data["event_type"] == "authentication"
    assert data["source_ip"] == "192.168.1.50"
    assert data["outcome"] == "failure"
    assert "id" in data
    assert "ingested_at" in data


def test_retrieve_security_event(client):
    created = client.post(
        "/api/v1/events",
        json=sample_payload(),
    )

    event_id = created.json()["id"]

    response = client.get(f"/api/v1/events/{event_id}")

    assert response.status_code == 200
    assert response.json()["id"] == event_id


def test_missing_event_returns_404(client):
    response = client.get(
        "/api/v1/events/00000000-0000-0000-0000-000000000000"
    )

    assert response.status_code == 404


def test_list_security_events(client):
    client.post("/api/v1/events", json=sample_payload())
    client.post(
        "/api/v1/events",
        json=sample_payload(
            event_type="network",
            source="firewall",
        ),
    )

    response = client.get("/api/v1/events")

    assert response.status_code == 200
    assert len(response.json()) == 2


def test_filter_events_by_type(client):
    client.post("/api/v1/events", json=sample_payload())
    client.post(
        "/api/v1/events",
        json=sample_payload(
            event_type="network",
            source="firewall",
        ),
    )

    response = client.get(
        "/api/v1/events",
        params={"event_type": "network"},
    )

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["event_type"] == "network"


def test_reject_blank_event_type(client):
    response = client.post(
        "/api/v1/events",
        json=sample_payload(event_type="   "),
    )

    assert response.status_code == 422


def test_reject_extra_fields(client):
    payload = sample_payload(unexpected_field="not allowed")

    response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert response.status_code == 422


def test_reject_oversized_details(client):
    payload = sample_payload(
        details={"payload": "x" * 17_000}
    )

    response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert response.status_code == 422


def test_reject_invalid_ip_address(client):
    response = client.post(
        "/api/v1/events",
        json=sample_payload(source_ip="999.999.999.999"),
    )

    assert response.status_code == 422

# ============================================================
# PHASE 2 - THREAT DETECTION TESTS
# ============================================================

from datetime import datetime, timedelta, timezone


def test_brute_force_detection(client):
    base = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)

    for attempt in range(5):
        response = client.post(
            "/api/v1/events",
            json=sample_payload(
                source_ip="203.0.113.10",
                username="admin",
                outcome="failure",
                occurred_at=(
                    base + timedelta(minutes=attempt)
                ).isoformat(),
            ),
        )
        assert response.status_code == 201

    incidents = client.get("/api/v1/incidents").json()

    matches = [
        x for x in incidents
        if x["rule_id"] == "BRUTE_FORCE_AUTH"
    ]

    assert len(matches) == 1
    assert matches[0]["severity"] == "high"
    assert matches[0]["risk_score"] == 80
    assert matches[0]["event_count"] == 5


def test_suspicious_authentication_detection(client):
    response = client.post(
        "/api/v1/events",
        json=sample_payload(
            source_ip="203.0.113.20",
            outcome="success",
            details={
                "method": "ssh",
                "new_device": True,
            },
        ),
    )

    assert response.status_code == 201

    incidents = client.get("/api/v1/incidents").json()

    matches = [
        x for x in incidents
        if x["rule_id"] == "SUSPICIOUS_AUTH"
    ]

    assert len(matches) == 1
    assert matches[0]["severity"] == "high"
    assert "new_device" in matches[0]["description"]


def test_success_after_repeated_failures(client):
    base = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)

    for attempt in range(3):
        response = client.post(
            "/api/v1/events",
            json=sample_payload(
                source_ip="203.0.113.21",
                username="administrator",
                outcome="failure",
                occurred_at=(
                    base + timedelta(minutes=attempt)
                ).isoformat(),
            ),
        )
        assert response.status_code == 201

    response = client.post(
        "/api/v1/events",
        json=sample_payload(
            source_ip="203.0.113.21",
            username="administrator",
            outcome="success",
            occurred_at=(
                base + timedelta(minutes=3)
            ).isoformat(),
        ),
    )

    assert response.status_code == 201

    incidents = client.get("/api/v1/incidents").json()

    assert any(
        x["rule_id"] == "SUSPICIOUS_AUTH"
        for x in incidents
    )


def test_port_scan_detection(client):
    base = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)

    for index in range(10):
        response = client.post(
            "/api/v1/events",
            json={
                "event_type": "network_connection",
                "source": "test-firewall",
                "source_ip": "203.0.113.30",
                "outcome": "unknown",
                "occurred_at": (
                    base + timedelta(seconds=index * 20)
                ).isoformat(),
                "details": {
                    "destination_port": 1000 + index,
                    "protocol": "TCP",
                },
            },
        )

        assert response.status_code == 201

    incidents = client.get("/api/v1/incidents").json()

    matches = [
        x for x in incidents
        if x["rule_id"] == "PORT_SCAN"
    ]

    assert len(matches) == 1
    assert matches[0]["event_count"] == 10
    assert matches[0]["risk_score"] >= 85


def test_privilege_escalation_detection(client):
    response = client.post(
        "/api/v1/events",
        json={
            "event_type": "privilege_escalation",
            "source": "linux-server",
            "source_ip": "203.0.113.40",
            "username": "operator",
            "outcome": "success",
            "details": {
                "action": "sudo",
                "target": "root",
            },
        },
    )

    assert response.status_code == 201

    incidents = client.get("/api/v1/incidents").json()

    matches = [
        x for x in incidents
        if x["rule_id"] == "PRIVILEGE_ESCALATION"
    ]

    assert len(matches) == 1
    assert matches[0]["severity"] == "critical"
    assert matches[0]["risk_score"] == 95


def test_risk_scoring_and_incident_priority(client):
    from app.services.detection_service import (
        calculate_risk_score,
        severity_for_score,
    )

    assert calculate_risk_score(70, 8, 5) == 76
    assert severity_for_score(95) == "critical"
    assert severity_for_score(80) == "high"
    assert severity_for_score(60) == "medium"
    assert severity_for_score(20) == "low"

    client.post(
        "/api/v1/events",
        json={
            "event_type": "privilege_escalation",
            "source": "linux-server",
            "source_ip": "203.0.113.50",
            "outcome": "success",
            "details": {
                "privilege_escalation": True,
            },
        },
    )

    response = client.get(
        "/api/v1/incidents",
        params={
            "severity": "critical",
            "status": "open",
        },
    )

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["risk_score"] >= 90


def test_retrieve_incident_by_id(client):
    client.post(
        "/api/v1/events",
        json={
            "event_type": "privilege_escalation",
            "source": "linux-server",
            "source_ip": "203.0.113.60",
            "outcome": "success",
            "details": {
                "action": "grant_admin",
            },
        },
    )

    incidents = client.get("/api/v1/incidents").json()

    assert len(incidents) == 1

    incident_id = incidents[0]["id"]

    response = client.get(
        f"/api/v1/incidents/{incident_id}"
    )

    assert response.status_code == 200
    assert response.json()["id"] == incident_id


def test_missing_incident_returns_404(client):
    response = client.get(
        "/api/v1/incidents/"
        "00000000-0000-0000-0000-000000000000"
    )

    assert response.status_code == 404
