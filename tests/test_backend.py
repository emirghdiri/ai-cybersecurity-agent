"""API FastAPI et configuration de la collecte live (sans VM ni reseau)."""
import pytest
from fastapi.testclient import TestClient

from backend import live_collector as lc
from backend.main import app, validate_collector

client = TestClient(app)
SSH_VARS = [f"{m}_SSH_{k}" for m in ("KALI", "UBUNTU") for k in ("HOST", "USER", "PASSWORD", "KEY")]


@pytest.fixture
def no_ssh_env(monkeypatch):
    for var in SSH_VARS + ["NMAP_TARGET"]:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def ssh_env(monkeypatch, no_ssh_env):
    for k, v in {"KALI_SSH_HOST": "10.0.0.5", "KALI_SSH_USER": "kali", "KALI_SSH_PASSWORD": "x",
                 "UBUNTU_SSH_HOST": "10.0.0.10", "UBUNTU_SSH_USER": "arij",
                 "UBUNTU_SSH_PASSWORD": "y"}.items():
        monkeypatch.setenv(k, v)


def test_health():
    assert client.get("/health").json()["status"] == "ok"


def test_frontend_is_not_cached():
    r = client.get("/app/app.js")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-cache"


def test_collect_without_configuration_gives_clear_error(no_ssh_env):
    r = client.post("/collect-and-analyze")
    assert r.status_code == 503
    assert "KALI_SSH_HOST" in r.json()["detail"] and "UBUNTU_SSH_HOST" in r.json()["detail"]


def test_nmap_target_must_be_ipv4(ssh_env, monkeypatch):
    monkeypatch.setenv("NMAP_TARGET", "10.0.0.10; rm -rf /")
    with pytest.raises(lc.CollectorConfigError):
        lc.load_config()


def test_sudoers_rule_matches_exact_scan_command(ssh_env):
    cfg = lc.load_config()
    assert lc.nmap_command(cfg) == ["/usr/bin/nmap", "-sV", "-T4", "-p-", "-oX",
                                    "/home/kali/sentinelpath_nmap.xml", "10.0.0.10"]
    assert lc.guide_sudoers(cfg) == ("kali ALL=(root) NOPASSWD: /usr/bin/nmap -sV -T4 -p- -oX "
                                     "/home/kali/sentinelpath_nmap.xml 10.0.0.10")


def test_validate_collector():
    assert validate_collector({"hosts": [{"services": [{"name": "x", "port": 1}]}],
                               "relations": []}) == []
    assert validate_collector({"hosts": [], "relations": "?"})
