"""Analyseur de vulnerabilites (vulnerability/analyzer.py), sans appel a NVD."""
import analyzer


def test_build_cpe():
    assert analyzer.build_cpe("httpd", "2.4.49") == "cpe:2.3:a:apache:http_server:2.4.49"
    assert analyzer.build_cpe("openssh", "8.9p1") == "cpe:2.3:a:openbsd:openssh:8.9:p1"
    assert analyzer.build_cpe("redis", "7.2") == "cpe:2.3:a:redis:redis:7.2"
    assert analyzer.build_cpe("service-inconnu", "1.0") is None


def test_parse_cve_keeps_cisa_kev():
    raw = {"id": "CVE-2021-41773", "descriptions": [{"lang": "en", "value": "path traversal"}],
           "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
               "baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/..."}}]},
           "references": [], "cisaExploitAdd": "2021-11-03"}
    parsed = analyzer.parse_cve(raw)
    assert parsed["cvss"] == 9.8 and parsed["severity"] == "CRITICAL"
    assert parsed["kev"] is True and parsed["kev_added"] == "2021-11-03"
    raw.pop("cisaExploitAdd")
    assert analyzer.parse_cve(raw)["kev"] is False


def test_cache_entries_without_kev_are_refetched(monkeypatch):
    fetched = []
    monkeypatch.setattr(analyzer, "get_cached", lambda s, v: [{"id": "OLD", "cvss": 5.0}])
    monkeypatch.setattr(analyzer, "save_cache", lambda *a: None)
    monkeypatch.setattr(analyzer, "fetch_from_nvd",
                        lambda cpe: fetched.append(cpe) or [{"id": "NEW", "kev": False}])
    assert analyzer.get_vulnerabilities("httpd", "2.4.49") == [{"id": "NEW", "kev": False}]
    assert fetched == ["cpe:2.3:a:apache:http_server:2.4.49"]


def test_up_to_date_cache_is_used(monkeypatch):
    monkeypatch.setattr(analyzer, "get_cached", lambda s, v: [{"id": "C", "kev": True}])
    monkeypatch.setattr(analyzer, "fetch_from_nvd", lambda cpe: (_ for _ in ()).throw(AssertionError))
    assert analyzer.get_vulnerabilities("httpd", "2.4.49") == [{"id": "C", "kev": True}]
