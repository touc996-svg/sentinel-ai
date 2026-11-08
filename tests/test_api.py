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
