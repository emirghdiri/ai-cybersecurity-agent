"""Authentification : acces refuse sans connexion, sessions signees, anti-force brute."""
import pytest
from fastapi.testclient import TestClient

from backend import auth
from backend.main import app, safe_next

PASSWORD = "mot-de-passe-de-test-123"
HASH = auth.hash_password(PASSWORD, iterations=1000)  # rapide pour les tests


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.delenv("SENTINELPATH_AUTH", raising=False)
    monkeypatch.setenv("SENTINELPATH_USER", "admin")
    monkeypatch.setenv("SENTINELPATH_PASSWORD_HASH", HASH)
    monkeypatch.setattr(auth, "_failures", [])
    monkeypatch.setattr(auth, "_locked_until", 0.0)
    return TestClient(app, base_url="https://testserver")


def login(client, password=PASSWORD, next_path="/app/"):
    return client.post("/login", data={"username": "admin", "password": password, "next": next_path},
                       follow_redirects=False)


def test_password_hashing():
    assert auth.verify_password(PASSWORD, HASH)
    assert not auth.verify_password("mauvais", HASH)
    assert PASSWORD not in HASH


def test_closed_by_default_without_password(monkeypatch):
    monkeypatch.delenv("SENTINELPATH_AUTH", raising=False)
    monkeypatch.delenv("SENTINELPATH_PASSWORD_HASH", raising=False)
    r = TestClient(app).get("/analyses")
    assert r.status_code == 503 and "non configurée" in r.json()["detail"]


def test_protected_routes_require_login(enabled):
    for path in ("/analyses", "/vulnerabilities", "/openapi.json"):
        assert enabled.get(path).status_code == 401
    assert enabled.post("/collect-and-analyze").status_code == 401
    assert enabled.post("/chat", json={"question": "x"}).status_code == 401
    page = enabled.get("/app/", headers={"accept": "text/html"}, follow_redirects=False)
    assert page.status_code == 303 and page.headers["location"].startswith("/login")
    assert enabled.get("/health").status_code == 200  # route publique


def test_login_flow_and_secure_cookie(enabled):
    r = login(enabled, next_path="/app/")
    assert r.status_code == 303 and r.headers["location"] == "/app/"
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie
    assert enabled.get("/collect-status").status_code == 200   # session acceptee
    enabled.post("/logout")
    assert enabled.get("/collect-status").status_code == 401   # session supprimee


def test_wrong_password_and_tampered_cookie(enabled):
    assert login(enabled, password="faux").status_code == 401
    token = auth.create_session("admin")
    payload, signature = token.split(".")
    enabled.cookies.set(auth.SESSION_COOKIE, payload + "x." + signature)
    assert enabled.get("/analyses").status_code == 401


def test_brute_force_lockout(enabled):
    for _ in range(auth.MAX_FAILURES):
        login(enabled, password="faux")
    r = login(enabled)  # bon mot de passe, mais compte bloque temporairement
    assert r.status_code == 401 and "Trop de tentatives" in r.text


def test_no_open_redirect():
    assert safe_next("//evil.example") == "/app/"
    assert safe_next("https://evil.example") == "/app/"
    assert safe_next("/\evil.example") == "/app/"
    assert safe_next("/app/#graph") == "/app/#graph"


def test_security_headers():
    r = TestClient(app).get("/health")
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_agent_token_grants_api_access(enabled):
    import sentinelpath_agent as agent
    headers = agent.auth_headers()                      # meme calcul que le serveur
    assert headers["Authorization"] == f"Bearer {auth.agent_token()}"
    assert enabled.get("/analyses", headers=headers).status_code == 200
    assert enabled.get("/analyses", headers={"Authorization": "Bearer faux"}).status_code == 401


def test_without_password_only_local_and_tailnet(monkeypatch):
    monkeypatch.setenv("SENTINELPATH_AUTH", "disabled")
    c = TestClient(app)
    assert c.get("/collect-status").status_code == 200                       # ce PC
    tailnet = {"x-forwarded-for": "100.102.201.55", "tailscale-user-login": "arij@example.com"}
    assert c.get("/collect-status", headers=tailnet).status_code == 200       # tailscale serve
    internet = {"x-forwarded-for": "203.0.113.7"}
    r = c.get("/collect-status", headers=internet)                            # Funnel / internet
    assert r.status_code == 403 and "internet refusé" in r.json()["detail"]
