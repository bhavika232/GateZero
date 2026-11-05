import uuid


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ready_checks_database(client):
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_every_response_gets_a_server_generated_request_id(client):
    supplied = "attacker-chosen-id"
    response = client.get("/health", headers={"X-Request-ID": supplied})
    assert response.headers["X-Request-ID"] != supplied
    uuid.UUID(response.headers["X-Request-ID"])  # raises if not a UUID


def test_unknown_route_uses_error_envelope(client):
    response = client.get("/nope")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"
