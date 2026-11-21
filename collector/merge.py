#!/usr/bin/env python3
"""
Fusionne la vue interne et la vue externe de l'infrastructure :

  - local_inventory.json (vue interne, produit par local_inventory.py sur la machine)
  - nmap_scan.xml        (vue externe, scan Nmap lancé depuis la machine attaquante)

et produit collector_output.json, consommé par vulnerability/analyze_infra.py :

  - services : avec le champ exposed_externally (port vu "open" par Nmap)
  - relations : attaquant -> services exposés, puis pivots Docker
                (conteneur exposé -> conteneur non exposé sur un même réseau Docker)

Le scan Nmap attendu (depuis Kali) :
    nmap -sV -p- -oX nmap_scan.xml <IP_DE_LA_VM>

Usage :
    python3 collector/merge.py
    python3 collector/merge.py --inventory local_inventory.json \
        --nmap collector/nmap_scan.xml -o collector_output.json --attacker kali
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

# Versions qui ne sont pas de vraies versions (tag Docker par défaut, etc.)
NOT_A_VERSION = {None, "", "latest", "unknown"}


# --------------------------------------------------------------------------- #
# Lecture des entrées
# --------------------------------------------------------------------------- #
def load_inventory(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        sys.exit(f"Erreur : {path} introuvable (lancez d'abord collector/local_inventory.py)")
    except json.JSONDecodeError as exc:
        sys.exit(f"Erreur : {path} n'est pas un JSON valide ({exc})")


def parse_nmap(xml_path):
    """
    Renvoie {(port, proto): {"product", "version", "service", "cpe"}} pour les ports 'open'.
    Les champs product/version/cpe ne sont remplis que si Nmap a été lancé avec -sV.
    """
    try:
        root = ET.parse(xml_path).getroot()
    except FileNotFoundError:
        print(f"[!] {xml_path} introuvable : exposed_externally sera false partout.",
              file=sys.stderr)
        return {}
    except ET.ParseError as exc:
        print(f"[!] {xml_path} illisible ({exc}) : exposed_externally sera false partout.",
              file=sys.stderr)
        return {}

    open_ports = {}
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        cpe = svc.find("cpe") if svc is not None else None
        open_ports[(int(port.get("portid")), port.get("protocol", "tcp"))] = {
            "service": svc.get("name") if svc is not None else None,
            "product": svc.get("product") if svc is not None else None,
            "version": svc.get("version") if svc is not None else None,
            "cpe": cpe.text if cpe is not None else None,
        }
    return open_ports


# --------------------------------------------------------------------------- #
# Fusion des services
# --------------------------------------------------------------------------- #
def merge_service(svc, nmap_info):
    """
    Combine un service de l'inventaire local avec ce que Nmap en a vu.
    La version locale est prioritaire ; si elle est absente (ou 'latest'),
    on prend celle détectée par Nmap (-sV) et le nom du produit Nmap
    (ex. 'Apache httpd'), que l'analyseur de vulnérabilités sait reconnaître.
    """
    name, version, source = svc.get("name"), svc.get("version"), "local"
    if version in NOT_A_VERSION and nmap_info and nmap_info.get("version"):
        name = (nmap_info.get("product") or nmap_info.get("service") or name).lower()
        version = nmap_info["version"]
        source = "nmap"

    return {
        "port": svc["port"],
        "protocol": svc.get("protocol", "tcp"),
        "name": name,
        "version": None if version in NOT_A_VERSION else version,
        "version_source": source if version not in NOT_A_VERSION else None,
        "process": svc.get("process"),
        "container": svc.get("container"),
        "exposed_externally": nmap_info is not None,
        "nmap_cpe": nmap_info.get("cpe") if nmap_info else None,
    }


def nmap_only_service(port, proto, info):
    """Port ouvert vu par Nmap mais absent de l'inventaire local (ex. inventaire sans sudo)."""
    return {
        "port": port,
        "protocol": proto,
        "name": (info.get("product") or info.get("service") or "unknown").lower(),
        "version": info.get("version"),
        "version_source": "nmap" if info.get("version") else None,
        "process": None,
        "container": None,
        "exposed_externally": True,
        "nmap_cpe": info.get("cpe"),
    }


def version_from_tag(tag):
    """
    Version exploitable a partir d'une etiquette d'image Docker, ou None.
      '2.4.49' -> '2.4.49'   '7.2-alpine' -> '7.2'   '5.7' -> '5.7'
      'latest', '7', 'bookworm' -> None (pas assez precis : on ne devine pas)
    """
    if not tag or tag in NOT_A_VERSION:
        return None
    m = re.match(r"^(\d+\.\d+(?:\.\d+)*)", str(tag))
    return m.group(1) if m else None


def internal_container_services(inventory, known_containers):
    """
    Conteneurs INTERNES (aucun port publie) : invisibles pour le scan Nmap externe et
    absents des ports en ecoute de l'hote. Leur logiciel et leur version sont deduits de
    leur image Docker (ex. backup-server -> httpd:2.4.49), sans rien inventer : si
    l'etiquette n'est pas une version precise ('latest'), la version reste inconnue.
    Un seul service par conteneur (son plus petit port interne), pour ne pas compter
    deux fois les memes CVE (ex. mysql expose 3306 et 33060).
    """
    services = []
    for c in inventory.get("containers", []):
        name = c.get("name")
        if not name or name in known_containers:
            continue
        internal = sorted(p["container_port"] for p in c.get("ports", [])
                          if not p.get("published") and isinstance(p.get("container_port"), int))
        if not internal or any(p.get("published") for p in c.get("ports", [])):
            continue
        image_name = (c.get("image_name") or "").rsplit("/", 1)[-1].lower() or "unknown"
        version = version_from_tag(c.get("image_tag"))
        services.append({
            "port": internal[0],
            "protocol": next((p["protocol"] for p in c["ports"]
                              if p["container_port"] == internal[0]), "tcp"),
            "name": image_name,
            "version": version,
            "version_source": "docker-image" if version else None,
            "process": None,
            "container": name,
            "exposed_externally": False,
            "nmap_cpe": None,
        })
    return services


def build_services(inventory, nmap_ports):
    services, seen = [], set()
    for svc in inventory.get("services", []):
        key = (svc["port"], svc.get("protocol", "tcp"))
        seen.add(key)
        services.append(merge_service(svc, nmap_ports.get(key)))

    for (port, proto), info in sorted(nmap_ports.items()):
        if (port, proto) not in seen:
            services.append(nmap_only_service(port, proto, info))

    known = {s["container"] for s in services if s.get("container")}
    services += internal_container_services(inventory, known)

    return sorted(services, key=lambda s: (s["exposed_externally"] is False,
                                           s["protocol"], s["port"]))


# --------------------------------------------------------------------------- #
# Relations (chemins réseau possibles)
# --------------------------------------------------------------------------- #
def build_relations(services, inventory, attacker):
    relations, seen = [], set()

    def add(source, target, port, via):
        key = (source, target, port)
        if key not in seen:
            seen.add(key)
            relations.append({"source": source, "target": target, "port": port, "via": via})

    # 1. L'attaquant atteint directement chaque service exposé
    for svc in services:
        if svc["exposed_externally"]:
            add(attacker, svc["container"] or svc["name"], svc["port"], "network")

    # 2. Pivots Docker : un conteneur exposé peut joindre les conteneurs NON exposés
    #    qui partagent un réseau Docker avec lui (ex. lab-api -> lab-db sur internal_net)
    exposed = {s["container"] for s in services if s["exposed_externally"] and s["container"]}
    internal_ports = {
        c["name"]: sorted({p["container_port"] for p in c.get("ports", []) if not p["published"]},
                          key=str)
        for c in inventory.get("containers", [])
    }

    for net in inventory.get("docker_networks", []):
        members = [c["name"] for c in net.get("containers", []) if c.get("name")]
        for src in members:
            if src not in exposed:
                continue
            for dst in members:
                if dst == src or dst in exposed:
                    continue
                for port in internal_ports.get(dst) or [None]:
                    add(src, dst, port, f"docker:{net['name']}")

    return relations


# --------------------------------------------------------------------------- #
# Programme principal
# --------------------------------------------------------------------------- #
def merge(inventory, nmap_ports, attacker="kali"):
    """Fusion complete (utilisee en ligne de commande et par backend/live_collector.py)."""
    services = build_services(inventory, nmap_ports)
    return {
        "scan_date": datetime.now().isoformat(timespec="seconds"),
        "hosts": [{
            "hostname": inventory.get("hostname"),
            "ip": inventory.get("ip"),
            "os": (inventory.get("os") or {}).get("name"),
            "services": services,
        }],
        "relations": build_relations(services, inventory, attacker),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Fusionne local_inventory.json et un scan Nmap XML en collector_output.json")
    parser.add_argument("--inventory", default="local_inventory.json",
                        help="inventaire local (défaut : local_inventory.json)")
    parser.add_argument("--nmap", default="collector/nmap_scan.xml",
                        help="scan Nmap au format XML (défaut : collector/nmap_scan.xml)")
    parser.add_argument("-o", "--output", default="collector_output.json",
                        help="fichier de sortie (défaut : collector_output.json)")
    parser.add_argument("--attacker", default="kali",
                        help="nom de la machine attaquante (défaut : kali)")
    args = parser.parse_args()

    output = merge(load_inventory(args.inventory), parse_nmap(args.nmap), args.attacker)
    services, relations = output["hosts"][0]["services"], output["relations"]

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    nb_exposed = sum(s["exposed_externally"] for s in services)
    print(f"{args.output} écrit : {len(services)} service(s) dont {nb_exposed} exposé(s), "
          f"{len(relations)} relation(s).")


if __name__ == "__main__":
    main()
