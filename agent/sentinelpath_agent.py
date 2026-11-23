"""
SentinelPath - Agent IA (ligne de commande).

Principe : "les outils calculent, l'agent IA explique".
L'agent ne calcule et n'invente rien : il appelle l'API FastAPI de SentinelPath
(seule source de verite) via de vraies requetes HTTP, puis reformule les
resultats en francais.

Prerequis :
  - le backend tourne :  python -m uvicorn backend.main:app --reload
  - au moins une analyse existe (POST /analyze)
  - la variable d'environnement GROQ_API_KEY est definie

Variables d'environnement optionnelles :
  - SENTINELPATH_API_URL  (defaut : http://127.0.0.1:8000)
  - GROQ_MODEL            (defaut : openai/gpt-oss-20b)

Usage :
  python agent/sentinelpath_agent.py
  python agent/sentinelpath_agent.py --debug     # affiche aussi les arguments des outils
"""
import argparse
import inspect
import json
import os
import re
import sys
import time
from collections import Counter

import requests
from groq import Groq, APIConnectionError, APIStatusError, BadRequestError, RateLimitError

API_URL = os.environ.get("SENTINELPATH_API_URL", "http://127.0.0.1:8000").rstrip("/")
MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")

HTTP_TIMEOUT = 30           # secondes
COLLECT_TIMEOUT = 900       # une collecte live (scan Nmap complet) peut prendre plusieurs minutes
MAX_TOOL_ROUNDS = 6         # appels d'outils max par question (evite les boucles infinies)
MAX_TOOL_CALL_RETRIES = 2   # nouveaux essais si Groq rejette un appel d'outil mal forme
MAX_TOOL_OUTPUT = 12_000    # caracteres max renvoyes au modele par outil (limite de tokens)
MAX_HISTORY_TURNS = 6       # questions/reponses gardees en memoire de conversation
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

DEBUG = False


# =========================================================================== #
# Acces au backend (seule source de verite)
# =========================================================================== #
class BackendError(Exception):
    """Erreur lisible a renvoyer au modele (backend arrete, analyse absente...)."""


def api_get(route, analysis_id=None):
    """GET sur le backend, avec des erreurs claires plutot qu'une exception brute."""
    params = {"analysis_id": analysis_id} if analysis_id is not None else None
    try:
        r = requests.get(f"{API_URL}{route}", params=params, timeout=HTTP_TIMEOUT)
    except requests.ConnectionError:
        raise BackendError(
            f"Backend injoignable sur {API_URL}. "
            "Lancez-le avec : python -m uvicorn backend.main:app --reload"
        )
    except requests.Timeout:
        raise BackendError(f"Le backend n'a pas repondu en {HTTP_TIMEOUT} s ({route}).")

    if r.status_code != 200:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        raise BackendError(f"{route} a repondu HTTP {r.status_code} : {detail}")
    return r.json()


def api_post(route, timeout=COLLECT_TIMEOUT):
    """POST sans corps sur le backend (lancement d'une collecte/analyse)."""
    try:
        r = requests.post(f"{API_URL}{route}", timeout=timeout)
    except requests.ConnectionError:
        raise BackendError(f"Backend injoignable sur {API_URL}.")
    except requests.Timeout:
        raise BackendError(f"{route} n'a pas termine en {timeout} s.")
    if r.status_code != 200:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        raise BackendError(f"{route} a repondu HTTP {r.status_code} : {detail}")
    return r.json()


# =========================================================================== #
# Outils exposes au LLM
# Chaque outil appelle UNE route du backend. Les seuls traitements faits ici
# sont deterministes (comptage, tri, filtrage) pour reduire la taille des
# donnees envoyees au modele : aucune donnee n'est inventee.
# =========================================================================== #
def list_analyses():
    """GET /analyses : historique des analyses avec leurs chiffres-cles."""
    return api_get("/analyses")


# Nom courant -> noms techniques EXACTS utilises dans les donnees (Nmap / collecteur).
# Uniquement pour la recherche : "apache" doit trouver "httpd". La correspondance est
# exacte et non par sous-chaine, sinon "httpd" capturerait aussi "werkzeug httpd" (Flask).
SERVICE_ALIASES = {
    "apache": ["httpd", "apache httpd", "apache"],
    "apache2": ["httpd", "apache httpd", "apache"],
    "flask": ["werkzeug httpd", "werkzeug", "flask", "flask-api"],
    "werkzeug": ["werkzeug httpd", "werkzeug"],
    "ssh": ["openssh", "ssh"],
    "sshd": ["openssh", "ssh"],
    "phpmyadmin": ["phpmyadmin"],
    "pma": ["phpmyadmin"],
    "mysql": ["mysql", "mariadb"],
    "mariadb": ["mariadb", "mysql"],
    "postgres": ["postgresql", "postgres"],
    "redis": ["redis"],
    "nginx": ["nginx"],
}


def norm(text):
    """'Backup Server', 'backup-server' et 'backup_server' -> 'backupserver'."""
    return re.sub(r"[\s_\-.]+", "", (text or "").lower())


def service_matches(query, name, port, container=None):
    """
    Le service correspond-il a la recherche ?
      - un numero cherche le port exact ("80" ne doit pas trouver 8080) ;
      - sinon : alias exact (apache -> httpd), ou nom/conteneur contenant le texte cherche
        (sans tenir compte des espaces, tirets et underscores).
    """
    q = query.lower().strip()
    if q.isdigit():
        return str(port) == q
    if norm(name) in {norm(a) for a in SERVICE_ALIASES.get(q, [])}:
        return True
    return norm(q) in norm(name) or (container is not None and norm(q) in norm(container))


def load_graph_safe(analysis_id=None):
    """Graphe de l'analyse, ou graphe vide si indisponible (le filtre reste utilisable)."""
    try:
        return api_get("/graph", analysis_id)
    except BackendError:
        return {"nodes": [], "edges": []}


def containers_by_port(graph):
    """Port -> nom du conteneur, d'apres le graphe (pour chercher par ex. 'web-server')."""
    return {n["port"]: n["id"] for n in graph.get("nodes", []) if n.get("port") is not None}


def unscanned_node_message(query, graph):
    """
    Un actif peut exister dans le graphe sans figurer dans le rapport de vulnerabilites :
    c'est le cas d'un conteneur INTERNE (aucun port publie), invisible pour le scan Nmap
    externe. Son logiciel et sa version sont alors inconnus : ses vulnerabilites ne sont
    pas "nulles" mais "non recherchables". Renvoie un message explicite, ou None.
    """
    facts = node_facts(graph)
    matches = [n for n in facts if norm(query) and norm(query) in norm(n)]
    if not matches:
        return None
    parts = []
    for n in matches:
        f = facts[n]
        sources = sorted({a["from_node"] for a in f["reachable_internally_from"]})
        where = ("actif INTERNE non expose a l'exterieur, joignable depuis "
                 + ", ".join(sources)) if sources else "actif sans relation connue"
        parts.append(
            f"'{n}' EXISTE dans le graphe d'attaque ({where}), mais aucun service ni version "
            f"n'a ete collecte pour lui (service : {f['service']}, version : {f['version']}). "
            "Ses vulnerabilites ne peuvent donc PAS etre recherchees : elles sont INCONNUES, "
            "ce qui ne veut PAS dire qu'il n'en a aucune."
        )
    return " ".join(parts)


def get_vulnerabilities(analysis_id=None, severity=None, service=None, limit=None,
                        exploited_only=False):
    """GET /vulnerabilities, resume : totaux par severite + CVE les plus graves par service."""
    data = api_get("/vulnerabilities", analysis_id)

    severity = severity.upper() if isinstance(severity, str) and severity.strip() else None
    service = service.lower().strip() if isinstance(service, str) and service.strip() else None
    graph = load_graph_safe(analysis_id)
    containers = containers_by_port(graph)
    # Par defaut : 3 CVE detaillees pour un service precis, 2 par service pour la vue
    # d'ensemble (sinon le resultat depasse la limite de taille sur une grosse infra).
    try:
        limit = max(1, min(int(limit), 15))
    except (TypeError, ValueError):
        limit = 3 if service else 2

    total = Counter()
    total_exploited = 0
    services_out, unidentified = [], []
    for host in data.get("hosts", []):
        for svc in host.get("services", []):
            vulns = svc.get("vulnerabilities", [])
            counts = Counter(v.get("severity") or "N/A" for v in vulns)
            total.update(counts)
            exploited = sum(1 for v in vulns if v.get("kev"))
            total_exploited += exploited

            # Le rapport indique le conteneur ; l'index par port ne sert que pour les
            # anciennes analyses (il confondrait deux conteneurs sur le meme port).
            container = svc.get("container") or (
                None if "container" in svc else containers.get(svc.get("port")))
            if service and not service_matches(service, svc.get("name"), svc.get("port"), container):
                continue

            if not service and not vulns and (svc.get("name") or "unknown") == "unknown":
                # ports systeme sans nom ni version : une ligne, pas une fiche complete
                unidentified.append(f"port {svc.get('port')}")
                continue

            selected = [v for v in vulns if (not severity or v.get("severity") == severity)
                        and (not exploited_only or v.get("kev"))]
            if exploited_only and not selected:
                continue  # on ne liste que les services ayant au moins une CVE exploitee
            selected.sort(key=lambda v: (v.get("cvss") or 0, bool(v.get("kev"))), reverse=True)

            services_out.append({
                "host": host.get("hostname"),
                "container": container or NOT_COLLECTED,
                "listening_port": svc.get("port") if svc.get("port") is not None else NOT_COLLECTED,
                "published_port": svc.get("port") if svc.get("exposed_externally")
                                  else NO_PUBLISHED_PORT,
                "service": svc.get("name"),
                "version": svc.get("version") or NOT_COLLECTED,
                "version_source": VERSION_SOURCES.get(svc.get("version_source"), NOT_COLLECTED),
                "exposed_externally": svc.get("exposed_externally", NOT_COLLECTED),
                "status": svc.get("status"),
                "cve_count": len(vulns),
                "exploited_in_wild_count": exploited,
                "by_severity": {s: counts[s] for s in SEVERITIES if counts[s]},
                "matching_cves": len(selected),
                "top_cves": [
                    {
                        "id": v.get("id"),
                        "cvss": v.get("cvss"),
                        "severity": v.get("severity"),
                        "exploited_in_wild": bool(v.get("kev")),
                        "description": (v.get("description") or "")[:220 if service else 140],
                        # liens de correctif seulement pour un service precis (taille limitee)
                        "patch_refs": (v.get("patch_refs") or [])[:2] if service
                                      else "demander un service precis pour les liens",
                    }
                    for v in selected[:limit]
                ],
            })

    result = {}
    if service and not services_out:
        # Trois cas a ne pas confondre : actif interne non scanne (present dans le graphe),
        # service absent de l'infrastructure, ou service present sans CVE.
        internal = unscanned_node_message(service, graph)
        if internal:
            result["message"] = internal
        else:
            present = sorted({f"{s.get('name')} (port {s.get('port')})"
                              for h in data.get("hosts", []) for s in h.get("services", [])})
            result["message"] = (
                f"Aucun service ni actif ne correspond a '{service}' dans cette analyse "
                f"(ni dans les services scannes, ni dans le graphe d'attaque) : il n'a pas "
                f"ete detecte (ce n'est PAS un service present sans CVE). "
                f"Services presents : {', '.join(present)}."
            )
    return result | {
        "scan_date": data.get("scan_date"),
        "total_cves": sum(total.values()),
        "total_by_severity": {s: total[s] for s in SEVERITIES if total[s]},
        "total_exploited_in_wild": total_exploited,
        # Comptages faits ici (le modele ne doit pas recompter lui-meme)
        "service_counts": {
            "listed_below": len(services_out),
            "exposed_externally": sum(1 for s in services_out if s["exposed_externally"] is True),
            "internal_not_exposed": sum(1 for s in services_out if s["exposed_externally"] is False),
            "unidentified_ports": len(unidentified),
        },
        "note": "CVE deduites de la version du logiciel (base NVD) : leur exploitabilite "
                "reelle sur cette machine n'a pas ete testee. exploited_in_wild = present "
                "dans le catalogue CISA KEV (exploitee par de vrais attaquants).",
        "filters": {"severity": severity, "service": service, "top_cves_per_service": limit,
                    "exploited_only": bool(exploited_only)},
        "services": services_out,
        "unidentified_services": (
            f"{len(unidentified)} port(s) en ecoute sans service ni version identifies "
            f"(donc sans CVE recherchable) : {', '.join(unidentified)}" if unidentified else None),
    }


# Les champs absents ou null sont remplaces par ces textes explicites : un "trou"
# dans les donnees pousse le modele a le combler avec une valeur plausible
# (ex. "port 5432 PostgreSQL"), alors qu'un texte "non disponible" est recopie tel quel.
NOT_COLLECTED = "NON DISPONIBLE (aucune donnee collectee)"
NO_PUBLISHED_PORT = "AUCUN PORT PUBLIE (non expose a l'exterieur)"
VERSION_SOURCES = {
    "docker-image": "deduite de l'etiquette de l'image Docker du conteneur",
    "nmap": "detectee par le scan Nmap",
    "local": "relevee sur la machine",
}


def node_facts(graph):
    """
    Faits connus sur chaque noeud du graphe, avec les absences rendues explicites.
    Les ports d'acces internes viennent des aretes (ex. api-service -> database:33060
    via un reseau Docker interne) : ce sont des donnees collectees, pas des deductions.
    """
    internal_access = {}
    for e in graph.get("edges", []):
        if e.get("source") == "kali":
            continue
        src, dst, port, via = e.get("source"), e.get("target"), e.get("port"), e.get("via")
        port_txt = f"sur son port {port}" if port is not None else "(port non disponible)"
        # Phrase generee par le code : evite que le modele attribue le port a la source.
        internal_access.setdefault(dst, []).append({
            "from_node": src,
            "target_port": port if port is not None else NOT_COLLECTED,
            "network": via,
            "fact": f"{src} peut joindre {dst} {port_txt} (reseau {via}).",
        })

    facts = {}
    for n in graph.get("nodes", []):
        if n.get("role") == "attacker":
            continue
        exposed = n.get("exposed_externally") is True
        port = n.get("port")
        facts[n["id"]] = {
            "exposed_externally": exposed,
            "published_port": port if exposed and port is not None
                              else (NO_PUBLISHED_PORT if not exposed else NOT_COLLECTED),
            "listening_port": port if port is not None else NOT_COLLECTED,
            "service": n.get("name") or NOT_COLLECTED,
            "version": n.get("version") or NOT_COLLECTED,
            "reachable_internally_from": internal_access.get(n["id"], []),
        }
    return facts


def get_attack_graph(analysis_id=None):
    """GET /graph : noeuds (services, exposition) et aretes (relations reseau)."""
    graph = api_get("/graph", analysis_id)
    return {"nodes": node_facts(graph), "edges": graph.get("edges", [])}


def get_attack_paths(analysis_id=None):
    """GET /attack-paths (+ GET /graph pour les faits connus sur chaque noeud des chemins)."""
    targets = api_get("/attack-paths", analysis_id)
    facts = node_facts(api_get("/graph", analysis_id))
    on_paths = {node for t in targets for p in t.get("paths", []) for node in p.get("path", [])}
    return {
        "targets": targets,
        "node_facts": {n: facts[n] for n in sorted(on_paths) if n in facts},
    }


def get_risk_analysis(analysis_id=None, limit=10):
    """GET /risk-analysis : chemins classes par score de risque (le plus critique d'abord)."""
    data = api_get("/risk-analysis", analysis_id)
    try:
        limit = max(1, min(int(limit), 50))
    except (TypeError, ValueError):
        limit = 10
    for path in data:
        for d in path.get("details", []):
            for field in ("port", "service", "version"):
                if d.get(field) is None:
                    d[field] = NOT_COLLECTED
    return {"total_paths": len(data), "paths_by_risk": data[:limit]}


def _analysis_snapshot(analysis_id):
    """Faits comparables d'une analyse : services, noeuds, chemins et leur risque."""
    vulns = api_get("/vulnerabilities", analysis_id)
    graph = api_get("/graph", analysis_id)
    try:
        risks = api_get("/risk-analysis", analysis_id)
    except BackendError:
        risks = []
    # Meme identifiant que les noeuds du graphe (conteneur, sinon nom du service).
    # Les anciennes analyses n'ont pas le champ "container" : on le retrouve par le port.
    port_to_node = {n["port"]: n["id"] for n in graph.get("nodes", []) if n.get("port") is not None}
    services = {}
    for h in vulns.get("hosts", []):
        for s in h.get("services", []):
            if (s.get("name") or "unknown") == "unknown":
                continue  # ports systeme sans nom : bruit, varient d'un scan a l'autre
            if "container" in s:
                key = s["container"] or s.get("name")
            else:
                key = port_to_node.get(s.get("port")) or s.get("name")
            services[key] = {"service": s.get("name"), "version": s.get("version"),
                             "port": s.get("port"),
                             "cve_count": len(s.get("vulnerabilities", []))}
    return {
        "services": services,
        "nodes": {n["id"] for n in graph.get("nodes", [])
                  if n.get("role") != "attacker" and n["id"] != "unknown"},
        "paths": {" -> ".join(r["path"]): r.get("risk_score") for r in risks},
    }


def compare_analyses(old_analysis_id, new_analysis_id):
    """Differences factuelles entre deux analyses enregistrees (calculees ici, pas par le LLM)."""
    summaries = {a["id"]: a for a in api_get("/analyses")}
    for aid in (old_analysis_id, new_analysis_id):
        if aid not in summaries:
            raise BackendError(f"Aucune analyse avec l'id {aid} (voir list_analyses).")
    old, new = _analysis_snapshot(old_analysis_id), _analysis_snapshot(new_analysis_id)
    so, sn = summaries[old_analysis_id], summaries[new_analysis_id]

    changed = {k: {"avant": old["services"][k], "apres": new["services"][k]}
               for k in sorted(old["services"].keys() & new["services"].keys())
               if old["services"][k]["version"] != new["services"][k]["version"]}
    risk_changes = {p: {"avant": old["paths"][p], "apres": new["paths"][p]}
                    for p in sorted(old["paths"].keys() & new["paths"].keys())
                    if old["paths"][p] != new["paths"][p]}
    return {
        "old_analysis": {"id": old_analysis_id, "date": so["analysis_date"],
                         "scan_date": so["scan_date"]},
        "new_analysis": {"id": new_analysis_id, "date": sn["analysis_date"],
                         "scan_date": sn["scan_date"]},
        "counts": {k: {"avant": so[k], "apres": sn[k],
                       "difference": round((sn[k] or 0) - (so[k] or 0), 1)}
                   for k in ("cve_count", "critical_count", "paths_count", "max_risk_score")},
        "services_added": {k: new["services"][k]
                           for k in sorted(new["services"].keys() - old["services"].keys())},
        "services_removed": {k: old["services"][k]
                             for k in sorted(old["services"].keys() - new["services"].keys())},
        "services_version_changed": changed,
        "nodes_added": sorted(new["nodes"] - old["nodes"]),
        "nodes_removed": sorted(old["nodes"] - new["nodes"]),
        "attack_paths_added": {p: new["paths"][p]
                               for p in sorted(new["paths"].keys() - old["paths"].keys())},
        "attack_paths_removed": {p: old["paths"][p]
                                 for p in sorted(old["paths"].keys() - new["paths"].keys())},
        "risk_score_changes": risk_changes,
    }


def launch_analysis():
    """
    OUTIL D'ACTION (les autres outils ne font que lire) : POST /collect-and-analyze lance
    une vraie collecte en direct sur les VMs (scan Nmap complet depuis Kali + inventaire
    sur Ubuntu), l'analyse complete et l'enregistrement, puis compare avec l'analyse
    precedente. Timeout long (COLLECT_TIMEOUT) : le scan de tous les ports prend du temps.
    """
    history = api_get("/analyses")
    previous_id = history[0]["id"] if history else None
    print("  [..] Analyse en cours (scan Nmap + inventaire sur les VMs), "
          "ca peut prendre une minute...", flush=True)
    started = time.monotonic()
    result = api_post("/collect-and-analyze", timeout=COLLECT_TIMEOUT)
    print(f"  [ok] Nouvelle analyse #{result['analysis_id']} terminee en "
          f"{time.monotonic() - started:.0f} s.", flush=True)
    new_id = result["analysis_id"]
    out = {"new_analysis_id": new_id, "collection": result}
    if previous_id is not None:
        out["changes_since_previous"] = compare_analyses(previous_id, new_id)
    else:
        out["changes_since_previous"] = "Premiere analyse : aucune comparaison possible."
    return out


AVAILABLE_FUNCTIONS = {
    "list_analyses": list_analyses,
    "get_vulnerabilities": get_vulnerabilities,
    "get_attack_graph": get_attack_graph,
    "get_attack_paths": get_attack_paths,
    "get_risk_analysis": get_risk_analysis,
    "compare_analyses": compare_analyses,
    "launch_analysis": launch_analysis,
}

# Tous les parametres optionnels acceptent null : gpt-oss envoie souvent
# "analysis_id": null pour dire "la plus recente", et Groq rejette l'appel
# (HTTP 400 tool_use_failed) si le schema ne l'autorise pas.
ANALYSIS_ID_PARAM = {
    "type": ["integer", "null"],
    "description": "Identifiant d'une analyse precise (voir list_analyses). "
                   "Ne pas renseigner (ou null) pour utiliser la plus recente.",
}

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_analyses",
            "description": (
                "Historique de toutes les analyses enregistrees, de la plus recente a la plus "
                "ancienne, avec leurs chiffres-cles : id, date, nombre de services, nombre total "
                "de CVE, nombre de CVE critiques, nombre de chemins d'attaque, score de risque "
                "maximal. A utiliser pour : 'combien d'analyses', 'compare avec l'analyse "
                "precedente', 'evolution du risque', ou pour trouver un analysis_id."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_vulnerabilities",
            "description": (
                "Vulnerabilites connues (CVE de la base NVD, score CVSS, severite) de chaque "
                "service detecte : totaux par severite (CRITICAL, HIGH, MEDIUM, LOW), et pour "
                "chaque service les CVE les plus graves avec description et liens de correctif. "
                "A utiliser pour : 'combien de vulnerabilites critiques', 'quelles failles sur "
                "apache', 'quel service est le plus vulnerable', 'quelle CVE corriger en premier'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "analysis_id": ANALYSIS_ID_PARAM,
                    "severity": {
                        "type": ["string", "null"],
                        "enum": SEVERITIES + [None],
                        "description": "Ne lister que les CVE de cette severite.",
                    },
                    "service": {
                        "type": ["string", "null"],
                        "description": "Ne garder qu'un service : nom courant ou technique ('apache' "
                                       "trouve aussi 'httpd', 'flask' trouve 'werkzeug httpd', "
                                       "'ssh' trouve 'openssh'), nom de conteneur ('web-server') "
                                       "ou numero de port exact ('80').",
                    },
                    "limit": {
                        "type": ["integer", "null"],
                        "description": "Nombre de CVE detaillees par service (defaut 3, max 15).",
                    },
                    "exploited_only": {
                        "type": ["boolean", "null"],
                        "description": "true = ne lister que les CVE activement exploitees "
                                       "(catalogue CISA KEV). Pour 'quelles failles sont "
                                       "exploitees', 'quoi corriger en urgence'.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_attack_graph",
            "description": (
                "Graphe d'attaque de l'infrastructure : les noeuds (attaquant 'kali', services et "
                "conteneurs, avec port, version et exposition a l'exterieur) et les aretes "
                "(qui peut atteindre qui, par quel port, via le reseau externe ou un reseau Docker "
                "interne). A utiliser pour : 'quels services sont exposes', 'comment est organise "
                "le reseau', 'qui peut acceder a la base de donnees'."
            ),
            "parameters": {
                "type": "object",
                "properties": {"analysis_id": ANALYSIS_ID_PARAM},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_attack_paths",
            "description": (
                "Tous les chemins d'attaque possibles depuis l'attaquant vers chaque cible "
                "d'interet, avec la raison du choix de la cible ('not_exposed' = actif interne "
                "non expose comme une base de donnees, 'pivot' = point d'entree expose relie au "
                "reseau interne) et une description etape par etape, plus les faits connus sur "
                "chaque noeud traverse (port publie, ports d'acces internes, service, version ; "
                "'NON DISPONIBLE' si non collecte). Faits structurels seulement, sans score. "
                "A utiliser pour : 'quels chemins mènent a la base', 'comment un "
                "attaquant peut atteindre X', 'combien de chemins d'attaque'."
            ),
            "parameters": {
                "type": "object",
                "properties": {"analysis_id": ANALYSIS_ID_PARAM},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_risk_analysis",
            "description": (
                "Chemins d'attaque classes du plus dangereux au moins dangereux, avec pour chacun "
                "le score de risque (0-10), la severite, la CVE la plus grave a exploiter, le noeud "
                "ou elle se trouve, une explication, et le detail par service traverse. A utiliser "
                "pour : 'quel est le chemin le plus dangereux', 'que dois-je corriger en priorite', "
                "'quel est le niveau de risque', 'comment proteger ma base de donnees'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "analysis_id": ANALYSIS_ID_PARAM,
                    "limit": {
                        "type": ["integer", "null"],
                        "description": "Nombre de chemins renvoyes (defaut 10).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "compare_analyses",
            "description": (
                "Compare deux analyses enregistrees et renvoie les differences calculees : "
                "services ajoutes/retires, versions changees, noeuds ajoutes/retires, chemins "
                "d'attaque apparus/disparus, evolution des scores de risque et des nombres de CVE. "
                "A utiliser pour : 'qu'est-ce qui a change depuis la derniere analyse', "
                "'compare l'analyse 19 et 21'. Utiliser list_analyses pour trouver les id."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "old_analysis_id": {"type": "integer",
                                        "description": "Analyse la plus ancienne."},
                    "new_analysis_id": {"type": "integer",
                                        "description": "Analyse la plus recente."},
                },
                "required": ["old_analysis_id", "new_analysis_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "launch_analysis",
            "description": (
                "ACTION, pas une lecture : declenche une NOUVELLE collecte en direct sur les VMs "
                "(scan Nmap complet depuis Kali + inventaire sur Ubuntu, par SSH), puis l'analyse "
                "complete, l'enregistre comme nouvelle analyse et renvoie les differences avec la "
                "precedente. Ce n'est PAS une relecture des resultats existants : cela prend de "
                "20 secondes a plusieurs minutes et sollicite les machines. A appeler UNIQUEMENT "
                "si l'utilisateur le demande clairement ('relance une analyse', 'refais un scan', "
                "'analyse a nouveau mon infrastructure') ou confirme apres que tu le lui as "
                "propose. Jamais pour repondre a une question sur les resultats actuels."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]

SYSTEM_PROMPT = """Tu es l'agent IA de SentinelPath, un outil d'analyse de vulnerabilites et de chemins d'attaque.

Principe absolu : les outils calculent, toi tu expliques.
- Pour toute question sur l'infrastructure (services, CVE, chemins, risque, historique), appelle TOUJOURS au moins un outil avant de repondre. Ne reponds jamais de memoire.
- N'invente JAMAIS une CVE, un score CVSS, un score de risque, une version, un service ou un chemin d'attaque. Utilise uniquement les valeurs renvoyees par les outils, recopiees exactement.
- Donnees manquantes : si un champ (port, service, version...) est absent, null, ou vaut "NON DISPONIBLE" / "AUCUN PORT PUBLIE" dans le resultat d'un outil, dis explicitement que cette information n'est pas disponible ou que le port n'est pas publie. Ne le remplace JAMAIS par une valeur plausible, meme pour completer un tableau proprement : ecris "non disponible" dans la case.
- Ne deduis jamais un service ou une version a partir d'un numero de port ou du nom d'un noeud (un noeud nomme "database" n'est pas forcement PostgreSQL ou MySQL ; le port 6379 ne prouve pas Redis). Seuls les champs "service" et "version" font foi. N'ajoute donc jamais de nom de service entre parentheses apres un port : ecris "port 6379 (service non identifie)", pas "port 6379 (Redis)".
- Ne confonds jamais "aucune vulnerabilite trouvee" (service scanne, version connue, 0 CVE) et "vulnerabilites inconnues" (actif present dans le graphe mais dont le service/version n'a pas pu etre collecte, typiquement un conteneur interne sans port publie). Dans le second cas, dis que l'actif existe, ou il se trouve, et que ses vulnerabilites n'ont pas pu etre evaluees.
- Distingue le port publie vers l'exterieur ("published_port") des acces internes ("reachable_internally_from") : un actif non expose peut etre joignable en interne. Dans ce cas, "target_port" est le port de la CIBLE (pas celui de "from_node") ; reprends la phrase du champ "fact" telle quelle.
- Si un outil renvoie une erreur ou si l'information n'existe pas dans les donnees, dis-le clairement et indique quoi faire (par exemple lancer le backend ou une analyse). N'essaie pas de deviner.
- Pour les recommandations de securite, appuie-toi sur les faits renvoyes (CVE concernees, versions, chemins, liens de correctif) et propose des mesures concretes et reconnues (mise a jour vers une version corrigee, reduction de l'exposition, segmentation reseau, controle d'acces...). Precise que ce sont des recommandations generales a valider.
- Cite les identifiants exacts (CVE, noms des services/conteneurs, scores) pour que l'utilisateur puisse verifier.
- Les CVE sont deduites de la version du logiciel (base NVD) : ce sont des vulnerabilites potentielles, leur exploitabilite reelle sur la machine n'a pas ete testee ; dis-le quand tu presentes des CVE. Une CVE marquee exploited_in_wild figure dans le catalogue CISA KEV (exploitee par de vrais attaquants) : signale-la comme prioritaire.
- Si la version d'un service est "deduite de l'etiquette de l'image Docker", precise-le : c'est l'etiquette de l'image, pas une version mesuree.
- launch_analysis est le seul outil d'ACTION : il relance une vraie collecte sur les VMs (long, sollicite les machines). Ne l'appelle que si l'utilisateur le demande clairement et explicitement ("relance une analyse", "refais un scan", "analyse a nouveau mon infrastructure"), ou s'il vient de repondre oui a ta proposition de le faire. Ne l'appelle JAMAIS automatiquement pour repondre a une question sur les resultats existants : lis-les avec les autres outils.
- Si tu n'es pas sur que l'utilisateur veuille vraiment relancer une analyse complete (par exemple "est-ce que mon nouveau conteneur est pris en compte ?", "les resultats sont-ils a jour ?"), n'appelle PAS launch_analysis : reponds avec les donnees existantes (date de la derniere analyse via list_analyses) et demande-lui s'il veut que tu relances une analyse, en precisant que cela prend environ une minute.

Style : reponds en francais, de facon claire et structuree, concise (listes courtes plutot que longs paragraphes). Commence par la reponse directe a la question."""


# =========================================================================== #
# Boucle agent : question -> outils -> reponse
# =========================================================================== #
def parse_tool_args(func, raw_arguments):
    """
    Arguments JSON du modele -> dict utilisable par la fonction.
    gpt-oss renvoie parfois des arguments parasites comme {"": ""} : on ne garde
    que les parametres que la fonction accepte reellement, sans valeur vide.
    """
    try:
        args = json.loads(raw_arguments) if raw_arguments and raw_arguments.strip() else {}
    except json.JSONDecodeError:
        return {}
    if not isinstance(args, dict):
        return {}
    accepted = inspect.signature(func).parameters
    return {k: v for k, v in args.items() if k in accepted and v not in (None, "")}


def run_tool(name, raw_arguments, trace=None):
    """
    Execute un outil et renvoie son resultat sous forme de texte JSON pour le modele.
    Si `trace` est une liste, on y ajoute l'appel (outil, arguments, resultat exact
    transmis au modele) : le frontend l'affiche comme "sources" de la reponse.
    """
    func = AVAILABLE_FUNCTIONS.get(name)
    if func is None:
        text, args, ok = json.dumps({"error": f"Outil inconnu : {name}"}), {}, False
    else:
        args = parse_tool_args(func, raw_arguments)
        shown = ", ".join(f"{k}={v!r}" for k, v in args.items()) if DEBUG else ""
        print(f"  [outil] {name}({shown})")
        try:
            text, ok = json.dumps(func(**args), ensure_ascii=False), True
        except BackendError as e:
            print(f"  [!] {e}")
            text, ok = json.dumps({"error": str(e)}, ensure_ascii=False), False

    if len(text) > MAX_TOOL_OUTPUT:
        text = text[:MAX_TOOL_OUTPUT] + (
            ' ... [TRONQUE : resultat trop long. Utilise des filtres (service, severity, limit) '
            'pour obtenir le reste. Ne suppose rien sur la partie manquante.]'
        )
    if trace is not None:
        trace.append({"tool": name, "args": args, "ok": ok, "result": text})
    return text


def assistant_message_to_dict(msg):
    """Convertit la reponse du SDK en message 'assistant' reinjectable dans la conversation."""
    out = {"role": "assistant", "content": msg.content or ""}
    if msg.tool_calls:
        out["tool_calls"] = [
            {
                "id": c.id,
                "type": "function",
                "function": {"name": c.function.name, "arguments": c.function.arguments or "{}"},
            }
            for c in msg.tool_calls
        ]
    return out


def shrink_tool_results(messages, keep=2500):
    """Raccourcit les resultats d'outils deja envoyes ; renvoie True si quelque chose a change."""
    changed = False
    for m in messages:
        if isinstance(m, dict) and m.get("role") == "tool" and len(m["content"]) > keep:
            m["content"] = (m["content"][:keep] + ' ... [TRONQUE pour respecter la limite de '
                            'taille : ne suppose rien sur la partie manquante, utilise des '
                            'filtres plus precis si necessaire.]')
            changed = True
    return changed


def create_completion(client, messages, retries=MAX_TOOL_CALL_RETRIES):
    """
    Appel au modele. Si Groq rejette un appel d'outil mal forme genere par le
    modele (HTTP 400 'tool_use_failed'), on relance : le modele etant
    non deterministe, il produit en general un appel valide au 2e essai.
    """
    for attempt in range(retries + 1):
        try:
            return client.chat.completions.create(
                model=MODEL,
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
                temperature=0.2,  # reponses factuelles et stables
            )
        except BadRequestError as e:
            if "tool_use_failed" not in str(e) or attempt == retries:
                raise
            print("  [!] Appel d'outil mal forme par le modele, nouvel essai...")
        except APIStatusError as e:
            if e.status_code != 413 or attempt == retries or not shrink_tool_results(messages):
                raise
            print("  [!] Requete trop volumineuse pour Groq : resultats d'outils raccourcis...")


def normalize_answer(text):
    """
    Remplace les tirets typographiques du modele (U+2011 insecable, U+2010, U+2013)
    par le tiret ASCII : sinon "CVE‑2021‑41773" s'affiche correctement mais ne peut
    pas etre copie-colle dans une recherche NVD, ni compare aux donnees.
    """
    if not text:
        return text
    return text.translate({0x2010: "-", 0x2011: "-", 0x2013: "-"})


def ask(client, history, question, trace=None):
    """
    Traite une question : le modele appelle les outils necessaires puis repond.
    `trace` (liste optionnelle) recoit chaque appel d'outil, pour la tracabilite.
    """
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, *history,
                {"role": "user", "content": question}]

    for _ in range(MAX_TOOL_ROUNDS):
        response = create_completion(client, messages)
        msg = response.choices[0].message
        if not msg.tool_calls:
            return normalize_answer(msg.content) or "(reponse vide du modele)"

        messages.append(assistant_message_to_dict(msg))
        for call in msg.tool_calls:
            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": run_tool(call.function.name, call.function.arguments, trace),
            })

    return ("Je n'ai pas pu terminer : trop d'appels d'outils pour cette question. "
            "Essayez de la reformuler plus precisement.")


# =========================================================================== #
# Programme principal
# =========================================================================== #
def check_setup():
    """Verifie la cle Groq et le backend avant de demarrer la conversation."""
    if not os.environ.get("GROQ_API_KEY"):
        sys.exit(
            "Erreur : la variable d'environnement GROQ_API_KEY n'est pas definie.\n"
            "Definissez-la dans votre terminal (elle ne doit jamais etre ecrite dans le code)."
        )
    try:
        api_get("/health")
    except BackendError as e:
        sys.exit(f"Erreur : {e}")
    try:
        analyses = api_get("/analyses")
    except BackendError as e:
        sys.exit(f"Erreur : {e}")
    if not analyses:
        print("[!] Aucune analyse enregistree : lancez d'abord POST /analyze "
              f"(par exemple depuis {API_URL}/docs).")
    else:
        last = analyses[0]
        print(f"Backend OK ({API_URL}) - {len(analyses)} analyse(s), derniere : "
              f"#{last['id']} du {last['analysis_date']}")


def main():
    global DEBUG
    parser = argparse.ArgumentParser(description="Agent IA SentinelPath (ligne de commande)")
    parser.add_argument("--debug", action="store_true", help="affiche les arguments des outils")
    DEBUG = parser.parse_args().debug

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # accents corrects dans PowerShell

    check_setup()
    client = Groq(api_key=os.environ["GROQ_API_KEY"])
    history = []

    print(f"\nSentinelPath Agent ({MODEL}) - posez vos questions en francais.")
    print("Commandes : 'reset' pour oublier la conversation, 'quitter' pour sortir.\n")

    while True:
        try:
            question = input("Vous > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAu revoir.")
            break

        if not question:
            continue
        if question.lower() in {"quitter", "exit", "quit", "q"}:
            print("Au revoir.")
            break
        if question.lower() == "reset":
            history.clear()
            print("Conversation reinitialisee.\n")
            continue

        try:
            answer = ask(client, history, question)
        except RateLimitError:
            print("[!] Limite de requetes Groq atteinte (compte gratuit). "
                  "Attendez une minute puis reessayez.\n")
            continue
        except APIConnectionError:
            print("[!] Impossible de joindre l'API Groq (connexion Internet ?).\n")
            continue
        except APIStatusError as e:
            print(f"[!] Erreur de l'API Groq (HTTP {e.status_code}) : {e.message}\n")
            continue

        print(f"\nAgent > {answer}\n")

        # On ne garde que les questions/reponses (pas les gros resultats d'outils)
        # pour economiser les tokens : l'agent rappellera les outils si besoin.
        history += [{"role": "user", "content": question},
                    {"role": "assistant", "content": answer}]
        history[:] = history[-2 * MAX_HISTORY_TURNS:]


if __name__ == "__main__":
    main()
