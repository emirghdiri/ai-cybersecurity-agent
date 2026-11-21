"""Graphe, chemins d'attaque et score de risque (agent/attack_*.py, agent/risk_analyzer.py)."""
import pytest

import risk_analyzer as ra
from attack_graph_builder import build_graph
from attack_path_finder import find_attack_paths, find_candidate_targets

COLLECTOR = {
    "hosts": [{"services": [
        {"port": 80, "name": "httpd", "version": "2.4.49", "container": "web-server",
         "exposed_externally": True},
        {"port": 5000, "name": "werkzeug httpd", "version": "2.0.3", "container": "api-service",
         "exposed_externally": True},
        # meme port 80 que web-server : ne doit jamais recuperer ses CVE
        {"port": 80, "name": "httpd", "version": "2.4.20", "container": "backup-server",
         "exposed_externally": False},
    ]}],
    "relations": [
        {"source": "kali", "target": "web-server", "port": 80},
        {"source": "kali", "target": "api-service", "port": 5000},
        {"source": "api-service", "target": "backup-server", "port": 80, "via": "docker:internal"},
    ],
}


def cve(cid, cvss, kev=False):
    return {"id": cid, "cvss": cvss, "severity": "X", "kev": kev}


def report(api_vulns, backup_vulns, backup_first=False):
    web = {"port": 80, "container": "web-server", "name": "httpd",
           "vulnerabilities": [cve("CVE-WEB", 9.8, kev=True)]}
    api = {"port": 5000, "container": "api-service", "name": "werkzeug httpd",
           "vulnerabilities": api_vulns}
    backup = {"port": 80, "container": "backup-server", "name": "httpd",
              "vulnerabilities": backup_vulns}
    services = [backup, web, api] if backup_first else [web, api, backup]
    return {"hosts": [{"services": services}]}


def path_to(results, target):
    return next(r for r in results if r["path"][-1] == target and len(r["path"]) == 3)


def test_graph_and_targets():
    g = build_graph(COLLECTOR)
    targets = dict(find_candidate_targets(g))
    assert targets["backup-server"] == "not_exposed"
    assert targets["api-service"] == "pivot"
    assert [p["path"] for p in find_attack_paths(g, target="backup-server")] == \
        [["kali", "api-service", "backup-server"]]


@pytest.mark.parametrize("backup_first", [False, True])
def test_cves_matched_by_container_not_by_port(backup_first):
    """backup-server et web-server ecoutent tous deux sur le port 80 (quel que soit l'ordre)."""
    g = build_graph(COLLECTOR)
    res = ra.analyze_risk(g, report([cve("CVE-API", 5.0)], [cve("CVE-BACKUP", 6.0)], backup_first))
    path = path_to(res, "backup-server")
    backup = next(d for d in path["details"] if d["node"] == "backup-server")
    assert backup["nb_cve"] == 1 and backup["worst_cvss"] == 6.0  # pas le 9.8 de web-server
    assert path["exploited_cves"] == []                            # ni sa CVE exploitee


def test_kev_bonus_applied_and_capped():
    g = build_graph(COLLECTOR)
    no_kev = path_to(ra.analyze_risk(g, report([cve("A", 7.0)], [cve("B", 6.0)])), "backup-server")
    with_kev = path_to(ra.analyze_risk(g, report([cve("A", 7.0, kev=True)], [cve("B", 6.0)])),
                       "backup-server")
    assert no_kev["risk_score"] == 7.0 and no_kev["kev_bonus"] == 0
    assert with_kev["risk_score"] == 7.0 + ra.KEV_BONUS
    assert [e["id"] for e in with_kev["exploited_cves"]] == ["A"]
    capped = path_to(ra.analyze_risk(g, report([cve("A", 9.8, kev=True)], [])), "backup-server")
    assert capped["risk_score"] == 10.0


def test_pivot_weight():
    g = build_graph(COLLECTOR)
    pivot = next(r for r in ra.analyze_risk(g, report([cve("A", 9.0)], []))
                 if r["path"] == ["kali", "api-service"])
    assert pivot["risk_score"] == round(9.0 * ra.IMPACT_WEIGHT["pivot"], 1)


def test_description_when_worst_cve_is_on_target():
    g = build_graph(COLLECTOR)
    r = path_to(ra.analyze_risk(g, report([cve("A", 5.0)], [cve("B", 9.1)])), "backup-server")
    assert r["worst_node"] == "backup-server"
    assert "sur backup-server lui-meme" in r["description"]
    assert "doit d'abord" not in r["description"]


def test_old_reports_without_container_fall_back_to_port():
    g = build_graph(COLLECTOR)
    old = {"hosts": [{"services": [{"port": 5000, "name": "werkzeug httpd",
                                    "vulnerabilities": [cve("A", 8.0)]}]}]}
    r = next(r for r in ra.analyze_risk(g, old) if r["path"] == ["kali", "api-service"])
    assert r["base_cvss"] == 8.0
