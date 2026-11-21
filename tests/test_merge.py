"""Fusion inventaire local + scan Nmap (collector/merge.py)."""
import merge


def inventory():
    """Labo fictif : un web expose, une API exposee pivot, une base et un backup internes."""
    return {
        "hostname": "lab", "ip": "10.0.0.10", "os": {"name": "Ubuntu"},
        "services": [
            {"port": 80, "protocol": "tcp", "name": "httpd", "version": "2.4.49",
             "container": "web-server", "process": "docker-proxy"},
            {"port": 5000, "protocol": "tcp", "name": "lab-api", "version": "latest",
             "container": "api-service", "process": "docker-proxy"},
        ],
        "containers": [
            {"name": "web-server", "image_name": "httpd", "image_tag": "2.4.49",
             "ports": [{"container_port": 80, "host_port": 80, "protocol": "tcp", "published": True}]},
            {"name": "api-service", "image_name": "lab-api", "image_tag": "latest",
             "ports": [{"container_port": 5000, "host_port": 5000, "protocol": "tcp", "published": True}]},
            {"name": "database", "image_name": "mysql", "image_tag": "5.7",
             "ports": [{"container_port": 33060, "host_port": None, "protocol": "tcp", "published": False},
                       {"container_port": 3306, "host_port": None, "protocol": "tcp", "published": False}]},
            {"name": "backup-server", "image_name": "httpd", "image_tag": "2.4.49",
             "ports": [{"container_port": 80, "host_port": None, "protocol": "tcp", "published": False}]},
            {"name": "cache", "image_name": "library/redis", "image_tag": "latest",
             "ports": [{"container_port": 6379, "host_port": None, "protocol": "tcp", "published": False}]},
        ],
        "docker_networks": [
            {"name": "public", "containers": [{"name": "web-server"}, {"name": "api-service"}]},
            {"name": "internal", "containers": [{"name": "api-service"}, {"name": "database"},
                                                {"name": "backup-server"}, {"name": "cache"}]},
        ],
    }


NMAP = {
    (80, "tcp"): {"service": "http", "product": "Apache httpd", "version": "2.4.49", "cpe": None},
    (5000, "tcp"): {"service": "http", "product": "Werkzeug httpd", "version": "2.0.3", "cpe": None},
}


def by_container(output):
    return {s["container"]: s for s in output["hosts"][0]["services"] if s["container"]}


def test_version_from_tag_never_guesses():
    assert merge.version_from_tag("2.4.49") == "2.4.49"
    assert merge.version_from_tag("7.2-alpine") == "7.2"
    assert merge.version_from_tag("5.7") == "5.7"
    for imprecise in ("latest", "7", "bookworm", "", None):
        assert merge.version_from_tag(imprecise) is None


def test_internal_containers_get_version_from_image():
    services = by_container(merge.merge(inventory(), NMAP))
    db = services["database"]
    assert db["exposed_externally"] is False
    assert (db["name"], db["version"], db["version_source"]) == ("mysql", "5.7", "docker-image")
    assert db["port"] == 3306  # un seul service par conteneur : le plus petit port interne
    assert services["backup-server"]["version"] == "2.4.49"


def test_imprecise_image_tag_keeps_version_unknown():
    cache = by_container(merge.merge(inventory(), NMAP))["cache"]
    assert cache["name"] == "redis"          # chemin du registre retire
    assert cache["version"] is None and cache["version_source"] is None


def test_internal_container_counted_once():
    services = merge.merge(inventory(), NMAP)["hosts"][0]["services"]
    assert [s["container"] for s in services].count("database") == 1


def test_nmap_version_replaces_latest_tag():
    api = by_container(merge.merge(inventory(), NMAP))["api-service"]
    assert (api["name"], api["version"], api["version_source"]) == ("werkzeug httpd", "2.0.3", "nmap")
    assert api["exposed_externally"] is True


def test_relations_attacker_and_docker_pivots():
    rels = {(r["source"], r["target"]) for r in merge.merge(inventory(), NMAP)["relations"]}
    assert ("kali", "web-server") in rels and ("kali", "api-service") in rels
    assert ("api-service", "database") in rels and ("api-service", "backup-server") in rels
    assert ("web-server", "database") not in rels        # pas sur le reseau interne
    assert not any(t == "database" for s, t in rels if s == "kali")  # base jamais exposee
