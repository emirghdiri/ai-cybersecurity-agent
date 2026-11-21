"""
Calcule un score de risque pour chaque chemin d'attaque detecte par
attack_path_finder.py, en combinant les faits structurels (le chemin)
avec les CVE/CVSS reelles du Vulnerability Analyzer (vulnerability_report.json).

Principe :
  1. Le point de depart du score est la pire CVSS rencontree parmi les
     services traverses sur le chemin (un chemin n'est jamais plus sur
     que son maillon le plus faible).
  2. Ce score est pondere par la nature de la cible finale :
     - "not_exposed" (actif interne critique, ex. base de donnees, cache) :
       poids plein -> la compromission complete de l'actif est confirmee.
     - "pivot" (le chemin s'arrete sur un point d'entree, sans aller plus
       loin) : poids reduit -> seul un point d'entree est compromis, pas
       encore l'actif protege derriere.
  3. Si le chemin traverse au moins une CVE du catalogue CISA KEV (faille
     exploitee "dans la nature", information fournie par NVD), le score
     gagne KEV_BONUS (+1), plafonne a 10.
  Ces informations (CVSS reel, statut KEV, type de cible) sont deja
  calculees par les outils precedents : on ne fait que les combiner, sans
  inventer de nouvelle donnee. Les CVE des services sont retrouvees par
  noeud (conteneur), jamais par numero de port.
"""
import json
from pathlib import Path

from attack_graph_builder import load_collector_output, build_graph
from attack_path_finder import find_candidate_targets, find_attack_paths

VULN_REPORT = Path(__file__).parent.parent / "vulnerability" / "vulnerability_report.json"

IMPACT_WEIGHT = {
    "not_exposed": 1.0,   # la cible est un actif protege, atteint en entier
    "pivot": 0.6,          # seul un point d'entree est compromis
}

# Bonus si le chemin traverse au moins une CVE du catalogue CISA KEV (exploitee
# "dans la nature" par de vrais attaquants) : a CVSS egal, une faille activement
# exploitee est plus urgente qu'une faille theorique. Score plafonne a 10.
KEV_BONUS = 1.0


def load_vulnerability_report(path=VULN_REPORT):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_node_index(vuln_report):
    """
    Index noeud du graphe -> service du rapport de vulnerabilites.
    La cle est la meme que l'identifiant des noeuds (attack_graph_builder) :
    le conteneur, sinon le nom du service. Indexer par PORT melangeait les CVE de
    deux conteneurs differents ecoutant sur le meme port (ex. web-server et
    backup-server, tous deux sur le port 80).
    """
    index = {}
    for host in vuln_report.get("hosts", []):
        for svc in host.get("services", []):
            index.setdefault(svc.get("container") or svc.get("name"), svc)
    return index


def build_port_index(vuln_report):
    """Ancien index par port : uniquement pour les rapports sans champ 'container'."""
    index = {}
    for host in vuln_report.get("hosts", []):
        for svc in host.get("services", []):
            index.setdefault(svc["port"], svc)
    return index


def lookup_service(graph, node, node_index, port_index):
    """Service du rapport correspondant a un noeud : par identifiant, sinon par port."""
    if node in node_index:
        return node_index[node]
    port = graph.nodes[node].get("port")
    return port_index.get(port) if port is not None else None


def worst_cvss(vulns):
    scored = [v.get("cvss") for v in vulns if v.get("cvss") is not None]
    return max(scored) if scored else 0.0


def severity_label(score):
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INCONNU (pas de donnee CVE sur ce chemin)"


def score_path(graph, path, node_index, port_index=None):
    """Pire CVSS rencontre sur le chemin + detail par noeud traverse."""
    worst_score, worst_cve, worst_node, details, exploited = 0.0, None, None, [], []
    port_index = port_index or {}

    for node in path:
        if node == "kali":
            continue
        port = graph.nodes[node].get("port")
        entry = lookup_service(graph, node, node_index, port_index)
        vulns = entry.get("vulnerabilities", []) if entry else []
        node_worst = worst_cvss(vulns)

        details.append({
            "node": node,
            "port": port,
            "service": entry.get("name") if entry else None,
            "version": entry.get("version") if entry else None,
            "nb_cve": len(vulns),
            "nb_exploited": sum(1 for v in vulns if v.get("kev")),
            "worst_cvss": node_worst,
        })

        for v in vulns:
            if v.get("kev"):
                exploited.append({"id": v["id"], "cvss": v.get("cvss"), "node": node})

        if node_worst > worst_score:
            worst_score = node_worst
            # a CVSS egal, on retient de preference une CVE exploitee (KEV)
            worst_cve = max(vulns, key=lambda v: (v.get("cvss") or 0, bool(v.get("kev"))))
            worst_node = node

    return worst_score, worst_cve, worst_node, details, exploited


def describe_risk(target, reason, worst_node, worst_cve, exploited=()):
    """Explication humaine du risque, basee uniquement sur les faits calcules."""
    if worst_cve is None:
        return "Aucune donnee de vulnerabilite disponible pour ce chemin."

    if worst_node == target:
        sentence = (
            f"La faille la plus grave de ce chemin est sur {target} lui-meme : "
            f"{worst_cve['id']} (CVSS {worst_cve.get('cvss')})."
        )
    else:
        sentence = (
            f"Pour atteindre {target}, l'attaquant doit d'abord exploiter "
            f"{worst_cve['id']} (CVSS {worst_cve.get('cvss')}) sur {worst_node}."
        )
    if exploited:
        ids = ", ".join(sorted({e["id"] for e in exploited}))
        sentence += (f" Ce chemin traverse {len({e['id'] for e in exploited})} CVE "
                     f"activement exploitee(s) selon le catalogue CISA KEV ({ids}).")

    if reason == "not_exposed":
        sentence += (
            f" {target} est un actif interne normalement inaccessible depuis "
            f"l'exterieur : sa compromission signifie un acces complet a cette "
            f"ressource protegee."
        )
    else:
        sentence += (
            f" {target} est directement accessible depuis l'exterieur : "
            f"ce chemin represente un point d'entree, pas encore un acces a "
            f"un actif interne protege."
        )

    return sentence


def analyze_risk(graph, vuln_report):
    """Score chaque chemin d'attaque du graphe avec les CVSS du rapport de vulnerabilites."""
    has_containers = any("container" in s for h in vuln_report.get("hosts", [])
                         for s in h.get("services", []))
    node_index = build_node_index(vuln_report)
    port_index = {} if has_containers else build_port_index(vuln_report)

    results = []
    for target, reason in find_candidate_targets(graph):
        for p in find_attack_paths(graph, target=target):
            base_score, worst_cve, worst_node, details, exploited = score_path(
                graph, p["path"], node_index, port_index)
            bonus = KEV_BONUS if exploited else 0.0
            weighted_score = min(10.0, round(base_score * IMPACT_WEIGHT.get(reason, 1.0) + bonus, 1))

            results.append({
                "target": target,
                "reason": reason,
                "path": p["path"],
                "base_cvss": base_score,
                "risk_score": weighted_score,
                "severity": severity_label(weighted_score),
                "worst_cve": worst_cve["id"] if worst_cve else None,
                "worst_node": worst_node,
                "exploited_cves": exploited,
                "kev_bonus": bonus,
                "description": describe_risk(target, reason, worst_node, worst_cve, exploited),
                "details": details,
            })

    # Tri : score de risque, puis a score egal les chemins avec CVE exploitees d'abord
    return sorted(results, key=lambda r: (r["risk_score"], len(r["exploited_cves"])), reverse=True)


def main():
    graph = build_graph(load_collector_output())
    results = analyze_risk(graph, load_vulnerability_report())
    print(f"{len(results)} chemin(s) analyse(s), classes du plus critique au moins critique :\n")
    for r in results:
        print(f"[{r['severity']}] score={r['risk_score']} (base CVSS={r['base_cvss']})")
        print("   ", " -> ".join(r["path"]))
        print("   ", r["description"])
        print()


if __name__ == "__main__":
    main()