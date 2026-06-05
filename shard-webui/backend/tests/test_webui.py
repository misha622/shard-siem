import os
"""20 тестов для SHARD WebUI"""
import pytest
from httpx import AsyncClient, ASGITransport
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from app.main import app
from app.database import init_db, Base, engine

@pytest.fixture(autouse=True)
async def setup_db():
    Base.metadata.create_all(bind=engine)
    init_db()

@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

@pytest.fixture
async def auth_token(client):
    """Получить токен admin"""
    response = await client.post("/api/auth/login", json={"username": "admin", "password": os.getenv("ADMIN_PASSWORD", "admin123")})
    assert response.status_code == 200
    return response.json()["access_token"]

# === Auth tests ===
@pytest.mark.asyncio
async def test_login_success(client):
    response = await client.post("/api/auth/login", json={"username": "admin", "password": os.getenv("ADMIN_PASSWORD", "admin123")})
    assert response.status_code == 200
    assert "access_token" in response.json()

@pytest.mark.asyncio
async def test_login_failure(client):
    response = await client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_register(client):
    response = await client.post("/api/auth/register", json={"username": "testuser", "password": "TestPass123!", "email": "test@test.com", "first_name": "Test", "last_name": "User"})
    assert response.status_code in [201, 400]  # 400 if already exists

@pytest.mark.asyncio
async def test_refresh_token(client):
    login_resp = await client.post("/api/auth/login", json={"username": "admin", "password": os.getenv("ADMIN_PASSWORD", "admin123")})
    refresh = login_resp.json()["refresh_token"]
    response = await client.post("/api/auth/refresh", json={"refresh_token": refresh})
    assert response.status_code == 200
    assert "access_token" in response.json()

@pytest.mark.asyncio
async def test_me_endpoint(client, auth_token):
    response = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {auth_token}"})
    assert response.status_code == 200
    assert response.json()["username"] == "admin"

# === Alert tests ===
@pytest.mark.asyncio
async def test_get_alerts(client, auth_token):
    response = await client.get("/api/alerts/", headers={"Authorization": f"Bearer {auth_token}"})
    assert response.status_code == 200
    assert "alerts" in response.json()

@pytest.mark.asyncio
async def test_alerts_pagination(client, auth_token):
    response = await client.get("/api/alerts/?page=1&page_size=5", headers={"Authorization": f"Bearer {auth_token}"})
    assert response.status_code == 200
    assert response.json()["page"] == 1
    assert response.json()["page_size"] == 5

@pytest.mark.asyncio
async def test_alerts_filter_by_severity(client, auth_token):
    response = await client.get("/api/alerts/?severity=CRITICAL", headers={"Authorization": f"Bearer {auth_token}"})
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_alerts_export_csv(client, auth_token):
    response = await client.get("/api/alerts/export/csv", headers={"Authorization": f"Bearer {auth_token}"})
    assert response.status_code == 200
    assert "text/csv" in response.headers.get("content-type", "")

# === Stats tests ===
@pytest.mark.asyncio
async def test_dashboard_stats(client, auth_token):
    response = await client.get("/api/stats/dashboard", headers={"Authorization": f"Bearer {auth_token}"})
    assert response.status_code == 200
    assert "total_alerts" in response.json()

@pytest.mark.asyncio
async def test_system_metrics(client, auth_token):
    response = await client.get("/api/stats/system", headers={"Authorization": f"Bearer {auth_token}"})
    assert response.status_code == 200
    assert "cpu_percent" in response.json()

# === Blocked IPs tests ===
@pytest.mark.asyncio
async def test_get_blocked_ips(client, auth_token):
    response = await client.get("/api/blocked/", headers={"Authorization": f"Bearer {auth_token}"})
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_block_ip(client, auth_token):
    response = await client.post("/api/blocked/block", json={"ip_address": "10.0.0.99", "reason": "Test block"}, headers={"Authorization": f"Bearer {auth_token}"})
    assert response.status_code == 200
    assert "block_id" in response.json()

# === Company tests ===
@pytest.mark.asyncio
async def test_get_companies(client, auth_token):
    response = await client.get("/api/companies/", headers={"Authorization": f"Bearer {auth_token}"})
    assert response.status_code == 200

# === Settings tests ===
@pytest.mark.asyncio
async def test_system_info(client, auth_token):
    response = await client.get("/api/settings/system-info", headers={"Authorization": f"Bearer {auth_token}"})
    assert response.status_code == 200
    assert "os" in response.json()

@pytest.mark.asyncio
async def test_system_logs(client, auth_token):
    response = await client.get("/api/settings/logs?lines=10", headers={"Authorization": f"Bearer {auth_token}"})
    assert response.status_code == 200

# === Health test ===
@pytest.mark.asyncio
async def test_health(client):
    response = await client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

# === Unauthorized tests ===
@pytest.mark.asyncio
async def test_unauthorized_access(client):
    response = await client.get("/api/alerts/")
    assert response.status_code in [401, 403]

@pytest.mark.asyncio
async def test_unauthorized_blocked(client):
    response = await client.get("/api/blocked/")
    assert response.status_code in [401, 403]

# === Multi-tenant test ===
@pytest.mark.asyncio
async def test_viewer_login(client):
    response = await client.post("/api/auth/login", json={"username": "viewer", "password": "viewer123"})
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "viewer"
