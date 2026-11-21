"""Outils de l'agent IA (agent/sentinelpath_agent.py), avec un faux backend (sans reseau)."""
import json

import pytest

import sentinelpath_agent as agent

GRAPH = {
    "nodes": [
        {"id": "kali", "role": "attacker"},
        {"id": "web-server", "port": 80, "name": "httpd", "version": "2.4.49", "exposed_externally": True},
        {"id": "api-service", "port": 5000, "name": "werkzeug httpd", "version": "2.0.3",
         "exposed_externally": True},
        {"id": "database", "exposed_externally": False},
    ],
    "edges": [
        {"source": "kali", "target": "web-server", "port": 80, "via": "network"},
        {"source": "api-service", "target": "database", "port": 33060, "via": "docker:internal"},
    ],
}
VULNS = {"scan_date": "2026-11-21", "hosts": [{"hostname": "lab", "services": [
    {"port": 80, "container": "web-server", "exposed_externally": True, "name": "httpd",
     "version": "2.4.49", "version_source": "local", "status": "ok", "vulnerabilities": [
         {"id": "CVE-2021-41773", "cvss": 9.8, "severity": "CRITICAL", "kev": True},
         {"id": "CVE-X", "cvss": 5.0, "severity": "MEDIUM", "kev": False}]},
    {"port": 5000, "container": "api-service", "exposed_externally": True, "name": "werkzeug httpd",
     "version": "2.0.3", "status": "ok", "vulnerabilities": [
         {"id": "CVE-W", "cvss": 7.5, "severity": "HIGH", "kev": False}]},
    {"port": 53, "container": None, "exposed_externally": False, "name": "unknown",
     "version": None, "status": "version inconnue", "vulnerabilities": []},
]}]}


@pytest.fixture
def backend(monkeypatch):
    routes = {"/graph": GRAPH, "/vulnerabilities": VULNS}
    monkeypatch.setattr(agent, "api_get", lambda route, analysis_id=None: routes[route])
    monkeypatch.setattr(agent, "print", lambda *a, **k: None, raising=False)


def test_parse_tool_args_drops_parasites():
    assert agent.parse_tool_args(agent.get_risk_analysis, '{"": "", "analysis_id": null, "limit": 1}') \
        == {"limit": 1}
    assert agent.parse_tool_args(agent.list_analyses, "pas du json") == {}


def test_service_matching():
    assert agent.service_matches("apache", "httpd", 80)
    assert not agent.service_matches("apache", "werkzeug httpd", 5000)   # pas de melange
    assert agent.service_matches("80", "httpd", 80)
    assert not agent.service_matches("80", "tekbook", 8080)              # port exact
    assert agent.service_matches("backup server", "httpd", 80, "backup-server")


def test_normalize_answer_ascii_dashes():
    assert agent.normalize_answer("CVE‑2021‑41773") == "CVE-2021-41773"


def test_node_facts_make_missing_data_explicit():
    db = agent.node_facts(GRAPH)["database"]
    assert db["published_port"] == agent.NO_PUBLISHED_PORT
    assert db["service"] == agent.NOT_COLLECTED and db["version"] == agent.NOT_COLLECTED
    assert db["reachable_internally_from"][0]["fact"].startswith("api-service peut joindre database")


def test_unscanned_internal_node_is_not_reported_as_absent(backend):
    r = agent.get_vulnerabilities(service="database")
    assert r["services"] == []
    assert "EXISTE dans le graphe" in r["message"] and "INCONNUES" in r["message"]
    absent = agent.get_vulnerabilities(service="nginx")
    assert "n'a pas ete detecte" in absent["message"]


def test_vulnerabilities_summary_and_exploited_filter(backend):
    r = agent.get_vulnerabilities()
    assert r["total_cves"] == 3 and r["total_exploited_in_wild"] == 1
    assert r["service_counts"] == {"listed_below": 2, "exposed_externally": 2,
                                   "internal_not_exposed": 0, "unidentified_ports": 1}
    kev = agent.get_vulnerabilities(exploited_only=True)
    assert [s["container"] for s in kev["services"]] == ["web-server"]
    assert [c["id"] for c in kev["services"][0]["top_cves"]] == ["CVE-2021-41773"]


def test_published_vs_listening_port(backend):
    web = agent.get_vulnerabilities(service="apache")["services"][0]
    assert web["listening_port"] == 80 and web["published_port"] == 80


def test_shrink_tool_results():
    msgs = [{"role": "tool", "content": "x" * 9000}, {"role": "user", "content": "q"}]
    assert agent.shrink_tool_results(msgs) is True
    assert len(msgs[0]["content"]) < 3000 and msgs[1]["content"] == "q"


def test_compare_analyses(monkeypatch):
    old_vulns = {"hosts": [{"services": [  # ancienne analyse : pas de champ "container"
        {"port": 80, "name": "httpd", "version": "2.4.49", "vulnerabilities": []}]}]}
    graphs = {1: {"nodes": [{"id": "web-server", "port": 80}], "edges": []}, 2: GRAPH}
    vulns = {1: old_vulns, 2: VULNS}
    risks = {1: [], 2: [{"path": ["kali", "api-service", "database"], "risk_score": 9.8}]}
    summaries = [{"id": i, "analysis_date": "d", "scan_date": "s", "cve_count": c,
                  "critical_count": 0, "paths_count": p, "max_risk_score": m}
                 for i, c, p, m in ((1, 0, 0, None), (2, 3, 1, 9.8))]

    def fake(route, analysis_id=None):
        return {"/analyses": summaries, "/graph": graphs.get(analysis_id),
                "/vulnerabilities": vulns.get(analysis_id), "/risk-analysis": risks.get(analysis_id)}[route]
    monkeypatch.setattr(agent, "api_get", fake)

    diff = agent.compare_analyses(1, 2)
    assert list(diff["services_added"]) == ["api-service"]     # web-server reconnu dans les deux
    assert diff["services_removed"] == {}
    assert diff["attack_paths_added"] == {"kali -> api-service -> database": 9.8}
    assert diff["counts"]["cve_count"]["difference"] == 3
    with pytest.raises(agent.BackendError):
        agent.compare_analyses(1, 99)


def test_tool_schemas_are_consistent():
    names = {t["function"]["name"] for t in agent.TOOLS}
    assert names == set(agent.AVAILABLE_FUNCTIONS)
    json.dumps(agent.TOOLS)  # serialisable pour l'API Groq


def test_run_tool_records_trace(backend):
    trace = []
    text = agent.run_tool("get_vulnerabilities", '{"service": "apache", "": ""}', trace)
    assert trace == [{"tool": "get_vulnerabilities", "args": {"service": "apache"},
                      "ok": True, "result": text}]
    agent.run_tool("outil_inconnu", "{}", trace)
    assert trace[-1]["ok"] is False and trace[-1]["tool"] == "outil_inconnu"
