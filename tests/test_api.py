"""Tests for VCE-HQ API endpoints."""

from fastapi.testclient import TestClient
from vce_hq.api.app import create_app


def test_health_check() -> None:
    """Test the health check endpoint returns 200 OK."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_commitcode() -> None:
    """Test the commitcode endpoint returns git commit info."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/commitcode")
    assert response.status_code == 200
    data = response.json()
    assert "commit" in data
    commit = data["commit"]
    assert len(commit) > 0
