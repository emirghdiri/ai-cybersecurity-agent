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
  Ces deux informations (CVSS reel + type de cible) sont deja calculees
  par les outils precedents : on ne fait que les combiner, sans inventer
  de nouvelle donnee.
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


def load_vulnerability_report(path=VULN_REPORT):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_port_index(vuln_report):
    index = {}
    for host in vuln_report.get("hosts", []):
        for svc in host.get("services", []):
            index[svc["port"]] = svc
    return index


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


def score_path(graph, path, port_index):
    """Pire CVSS rencontre sur le chemin + detail par noeud traverse."""
    worst_score, worst_cve, worst_node, details = 0.0, None, None, []

    for node in path:
        if node == "kali":
            continue
        port = graph.nodes[node].get("port")
        entry = port_index.get(port) if port else None
        vulns = entry.get("vulnerabilities", []) if entry else []
        node_worst = worst_cvss(vulns)

        details.append({
            "node": node,
            "port": port,
            "service": entry.get("name") if entry else None,
            "version": entry.get("version") if entry else None,
            "nb_cve": len(vulns),
            "worst_cvss": node_worst,
        })

        if node_worst > worst_score:
            worst_score = node_worst
            worst_cve = max(vulns, key=lambda v: v.get("cvss") or 0) if vulns else None
            worst_node = node

    return worst_score, worst_cve, worst_node, details


def describe_risk(target, reason, worst_node, worst_cve):
    """Explication humaine du risque, basee uniquement sur les faits calcules."""
    if worst_cve is None:
        return "Aucune donnee de vulnerabilite disponible pour ce chemin."

    sentence = (
        f"Pour atteindre {target}, l'attaquant doit d'abord exploiter "
        f"{worst_cve['id']} (CVSS {worst_cve.get('cvss')}) sur {worst_node}."
    )

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


def analyze_risk():
    data = load_collector_output()
    graph = build_graph(data)
    vuln_report = load_vulnerability_report()
    port_index = build_port_index(vuln_report)

    results = []
    for target, reason in find_candidate_targets(graph):
        for p in find_attack_paths(graph, target=target):
            base_score, worst_cve, worst_node, details = score_path(graph, p["path"], port_index)
            weighted_score = round(base_score * IMPACT_WEIGHT.get(reason, 1.0), 1)

            results.append({
                "target": target,
                "reason": reason,
                "path": p["path"],
                "base_cvss": base_score,
                "risk_score": weighted_score,
                "severity": severity_label(weighted_score),
                "worst_cve": worst_cve["id"] if worst_cve else None,
                "worst_node": worst_node,
                "description": describe_risk(target, reason, worst_node, worst_cve),
                "details": details,
            })

    return sorted(results, key=lambda r: r["risk_score"], reverse=True)


def main():
    results = analyze_risk()
    print(f"{len(results)} chemin(s) analyse(s), classes du plus critique au moins critique :\n")
    for r in results:
        print(f"[{r['severity']}] score={r['risk_score']} (base CVSS={r['base_cvss']})")
        print("   ", " -> ".join(r["path"]))
        print("   ", r["description"])
        print()


if __name__ == "__main__":
    main()