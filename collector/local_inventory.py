#!/usr/bin/env python3
"""
Collecte locale de l'inventaire d'une machine Ubuntu.

Informations collectées :
  - hostname, IP principale, version de l'OS
  - ports TCP/UDP en écoute + processus associé (+ version si détectable)
  - conteneurs Docker actifs (nom, image, ports exposés, réseaux)
  - réseaux Docker et conteneurs connectés

Résultat écrit dans local_inventory.json.

Dépendances : bibliothèque standard + psutil (pip install psutil)

Usage :
    sudo python3 local_inventory.py                 # recommandé (voit tous les processus)
    python3 local_inventory.py -o /tmp/inv.json     # fichier de sortie personnalisé
"""

import argparse
import json
import platform
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime

try:
    import psutil
except ImportError:
    sys.exit("Erreur : le module psutil est requis. Installez-le avec : pip install psutil")


# Avertissements non bloquants remontés dans le JSON final
WARNINGS = []


# --------------------------------------------------------------------------- #
# Utilitaires
# --------------------------------------------------------------------------- #
def run_command(cmd, timeout=15):
    """Exécute une commande et renvoie (code_retour, stdout, stderr)."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout, res.stderr
    except FileNotFoundError:
        return 127, "", f"commande introuvable : {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"délai dépassé : {' '.join(cmd)}"
    except OSError as exc:
        return 1, "", str(exc)


def to_int(value):
    """Convertit en int si possible (les plages de ports '8000-8010' restent des chaînes)."""
    return int(value) if str(value).isdigit() else value


# --------------------------------------------------------------------------- #
# Système : hostname, IP, OS
# --------------------------------------------------------------------------- #
def get_hostname():
    return socket.gethostname()


def get_primary_ip():
    """
    IP de l'interface utilisée pour la route par défaut.
    Le connect() UDP n'envoie aucun paquet : il sert seulement à choisir l'interface.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        pass

    # Repli : première IPv4 non loopback d'une interface active
    stats = psutil.net_if_stats()
    for iface, addrs in psutil.net_if_addrs().items():
        if iface in stats and not stats[iface].isup:
            continue
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return addr.address
    return "127.0.0.1"


def get_os_info():
    """Lit /etc/os-release (format CLE=valeur)."""
    data = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    data[key] = value.strip().strip('"')
    except OSError:
        WARNINGS.append("/etc/os-release illisible : informations OS partielles")

    return {
        "name": data.get("PRETTY_NAME", platform.system()),
        "id": data.get("ID"),
        "version": data.get("VERSION_ID"),
        "codename": data.get("VERSION_CODENAME"),
        "kernel": platform.release(),
        "architecture": platform.machine(),
    }


# --------------------------------------------------------------------------- #
# Services : ports en écoute
# --------------------------------------------------------------------------- #
# Nom du processus -> (nom normalisé du service, commande de version, regex de version)
KNOWN_SERVICES = {
    "apache2":      ("apache",     ["-v"],        r"Apache/([\d.]+)"),
    "httpd":        ("apache",     ["-v"],        r"Apache/([\d.]+)"),
    "nginx":        ("nginx",      ["-v"],        r"nginx/([\d.]+)"),
    "sshd":         ("openssh",    ["-V"],        r"OpenSSH_([\w.]+)"),
    "mysqld":       ("mysql",      ["--version"], r"Ver ([\d.]+)"),
    "mariadbd":     ("mariadb",    ["--version"], r"Ver ([\d.]+)"),
    "postgres":     ("postgresql", ["--version"], r"([\d.]+)"),
    "redis-server": ("redis",      ["--version"], r"v=([\d.]+)"),
    "mongod":       ("mongodb",    ["--version"], r"v([\d.]+)"),
    "vsftpd":       ("vsftpd",     ["-v"],        r"([\d.]+)"),
    "named":        ("bind",       ["-v"],        r"BIND ([\d.]+)"),
    "dockerd":      ("docker",     ["--version"], r"version ([\d.]+)"),
}

_version_cache = {}


def detect_version(proc_name, exe_path):
    """Tente de récupérer la version d'un service connu en appelant son binaire."""
    known = KNOWN_SERVICES.get(proc_name)
    if not known:
        return None
    _, args, pattern = known
    binary = exe_path or shutil.which(proc_name)
    # sshd -V ne fonctionne pas sur toutes les versions : le client ssh donne la même version
    if proc_name == "sshd":
        binary = shutil.which("ssh") or binary
    if not binary:
        return None
    if binary in _version_cache:
        return _version_cache[binary]

    _, out, err = run_command([binary] + args, timeout=5)
    match = re.search(pattern, out + err)  # plusieurs outils écrivent la version sur stderr
    version = match.group(1) if match else None
    _version_cache[binary] = version
    return version


def get_listening_services(docker_port_map):
    """
    Liste les sockets TCP en LISTEN et les sockets UDP liés (sans adresse distante).
    docker_port_map : {(port, proto): conteneur} pour attribuer les ports publiés par Docker.
    """
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        WARNINGS.append("Accès refusé à la liste des connexions : relancez avec sudo")
        return []

    services = {}
    missing_pid = False

    for c in conns:
        if not c.laddr:
            continue
        if c.type == socket.SOCK_STREAM:
            if c.status != psutil.CONN_LISTEN:
                continue
            proto = "tcp"
        elif c.type == socket.SOCK_DGRAM:
            if c.raddr:  # socket UDP "connecté" = client, pas un service
                continue
            proto = "udp"
        else:
            continue

        port = c.laddr.port
        key = (port, proto)
        entry = services.get(key)
        if entry is None:
            entry = {
                "port": port,
                "protocol": proto,
                "addresses": [],
                "name": None,
                "process": None,
                "pid": c.pid,
                "version": None,
                "container": None,
            }
            services[key] = entry
        if c.laddr.ip not in entry["addresses"]:
            entry["addresses"].append(c.laddr.ip)

        if entry["process"] is None and c.pid:
            entry["pid"] = c.pid
            try:
                proc = psutil.Process(c.pid)
                proc_name = proc.name()
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    exe = None
                entry["process"] = proc_name
                entry["name"] = KNOWN_SERVICES.get(proc_name, (proc_name,))[0]
                entry["version"] = detect_version(proc_name, exe)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        elif not c.pid:
            missing_pid = True

    # Ports publiés par Docker (process docker-proxy ou règles iptables) -> conteneur
    for (port, proto), entry in services.items():
        container = docker_port_map.get((port, proto))
        if container:
            entry["container"] = container["name"]
            entry["name"] = container["image_name"]
            if entry["version"] is None:
                entry["version"] = container["image_tag"]

    for entry in services.values():
        if entry["name"] is None:
            entry["name"] = "unknown"

    if missing_pid:
        WARNINGS.append(
            "Certains ports n'ont pas de processus associé : relancez avec sudo pour tout voir"
        )

    return sorted(services.values(), key=lambda s: (s["protocol"], s["port"]))


# --------------------------------------------------------------------------- #
# Docker
# --------------------------------------------------------------------------- #
def docker_available():
    if shutil.which("docker") is None:
        WARNINGS.append("Docker non installé : conteneurs et réseaux ignorés")
        return False
    code, _, err = run_command(["docker", "info", "--format", "{{.ServerVersion}}"])
    if code != 0:
        hint = " (ajoutez l'utilisateur au groupe docker ou utilisez sudo)" \
            if "permission denied" in err.lower() else ""
        WARNINGS.append(f"Docker inaccessible : {err.strip()}{hint}")
        return False
    return True


def split_image(image):
    """'nginx:1.25' -> ('nginx', '1.25') ; gère les registres avec port (host:5000/img:tag)."""
    image = image.split("@", 1)[0]  # retire un éventuel digest
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = image.rsplit(":", 1)
    else:
        name, tag = image, "latest"
    return name, tag


def parse_docker_ports(ports_str):
    """
    Analyse la colonne Ports de 'docker ps', ex :
      '0.0.0.0:8080->80/tcp, :::8080->80/tcp, 3306/tcp'
    """
    result, seen = [], set()
    if not ports_str:
        return result
    for item in ports_str.split(","):
        item = item.strip()
        if "/" not in item:
            continue
        mapping, proto = item.rsplit("/", 1)
        if "->" in mapping:
            host, container_port = mapping.split("->", 1)
            host_ip, host_port = host.rsplit(":", 1)
            host_ip = host_ip.strip("[]") or "::"
        else:
            host_ip, host_port, container_port = None, None, mapping

        key = (host_port, container_port, proto)
        if key in seen:  # évite le doublon IPv4 / IPv6 d'un même mapping
            continue
        seen.add(key)
        result.append({
            "host_ip": host_ip,
            "host_port": to_int(host_port) if host_port else None,
            "container_port": to_int(container_port),
            "protocol": proto,
            "published": host_port is not None,
        })
    return result


def get_docker_containers():
    code, out, err = run_command(["docker", "ps", "--no-trunc", "--format", "{{json .}}"])
    if code != 0:
        WARNINGS.append(f"docker ps a échoué : {err.strip()}")
        return []

    containers = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        image_name, image_tag = split_image(raw.get("Image", ""))
        networks = raw.get("Networks", "")
        containers.append({
            "id": raw.get("ID", "")[:12],
            "name": raw.get("Names", ""),
            "image": raw.get("Image", ""),
            "image_name": image_name,
            "image_tag": image_tag,
            "status": raw.get("Status", ""),
            "ports": parse_docker_ports(raw.get("Ports", "")),
            "networks": [n for n in networks.split(",") if n],
        })
    return containers


def get_docker_networks():
    code, out, err = run_command(["docker", "network", "ls", "-q", "--no-trunc"])
    if code != 0:
        WARNINGS.append(f"docker network ls a échoué : {err.strip()}")
        return []
    ids = out.split()
    if not ids:
        return []

    code, out, err = run_command(["docker", "network", "inspect"] + ids)
    if code != 0:
        WARNINGS.append(f"docker network inspect a échoué : {err.strip()}")
        return []
    try:
        raw_networks = json.loads(out)
    except json.JSONDecodeError:
        WARNINGS.append("Sortie de docker network inspect illisible")
        return []

    networks = []
    for net in raw_networks:
        ipam = (net.get("IPAM") or {}).get("Config") or []
        connected = [
            {
                "name": info.get("Name"),
                "id": cid[:12],
                "ipv4": (info.get("IPv4Address") or "").split("/")[0] or None,
                "ipv6": (info.get("IPv6Address") or "").split("/")[0] or None,
            }
            for cid, info in (net.get("Containers") or {}).items()
        ]
        networks.append({
            "name": net.get("Name"),
            "id": (net.get("Id") or "")[:12],
            "driver": net.get("Driver"),
            "scope": net.get("Scope"),
            "internal": net.get("Internal", False),
            "subnets": [c.get("Subnet") for c in ipam if c.get("Subnet")],
            "gateways": [c.get("Gateway") for c in ipam if c.get("Gateway")],
            "containers": sorted(connected, key=lambda c: c["name"] or ""),
        })
    return sorted(networks, key=lambda n: n["name"] or "")


# --------------------------------------------------------------------------- #
# Programme principal
# --------------------------------------------------------------------------- #
def collect():
    containers, docker_networks = [], []
    if docker_available():
        containers = get_docker_containers()
        docker_networks = get_docker_networks()

    # (port_hôte, proto) -> conteneur, pour identifier les services publiés par Docker
    docker_port_map = {}
    for ctn in containers:
        for p in ctn["ports"]:
            if isinstance(p["host_port"], int):
                docker_port_map[(p["host_port"], p["protocol"])] = ctn

    services = get_listening_services(docker_port_map)

    return {
        "scan_date": datetime.now().isoformat(timespec="seconds"),
        "hostname": get_hostname(),
        "ip": get_primary_ip(),
        "os": get_os_info(),
        "services": services,
        "containers": containers,
        "docker_networks": docker_networks,
        "warnings": WARNINGS,
    }


def main():
    parser = argparse.ArgumentParser(description="Inventaire local d'une machine Ubuntu")
    parser.add_argument("-o", "--output", default="local_inventory.json",
                        help="fichier JSON de sortie (défaut : local_inventory.json)")
    args = parser.parse_args()

    if not sys.platform.startswith("linux"):
        print("Attention : ce script est prévu pour Linux (Ubuntu) ; résultats partiels possibles.",
              file=sys.stderr)

    inventory = collect()
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2, ensure_ascii=False)

    print(f"Inventaire écrit dans {args.output}")
    print(f"  {len(inventory['services'])} service(s), "
          f"{len(inventory['containers'])} conteneur(s), "
          f"{len(inventory['docker_networks'])} réseau(x) Docker")
    for w in WARNINGS:
        print(f"  [!] {w}", file=sys.stderr)


if __name__ == "__main__":
    main()
