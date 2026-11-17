"""
Chaine d'analyse complete de SentinelPath :
collector_output.json -> vulnerabilites (NVD) -> graphe d'attaque -> chemins d'attaque.

Ce fichier ne calcule rien lui-meme : il enchaine les modules existants
(vulnerability/ et agent/) et regroupe leurs resultats dans analysis_result.json.
"""
import json
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "backend" / "data"
COLLECTOR_FILE = DATA_DIR / "collector_output.json"
ANALYSIS_FILE = DATA_DIR / "analysis_result.json"

# Les modules vulnerability/ et agent/ s'importent "a plat"
# (ex. "from analyzer import ..."), on ajoute donc leurs dossiers au chemin Python.
for folder in ("vulnerability", "agent"):
    folder_path = str(BASE_DIR / folder)
    if folder_path not in sys.path:
        sys.path.insert(0, folder_path)

from analyze_infra import analyze_infrastructure  # noqa: E402
from attack_graph_builder import build_graph  # noqa: E402
from attack_path_finder import find_attack_paths, find_candidate_targets  # noqa: E402


def graph_to_dict(graph):
    """Convertit le graphe NetworkX en JSON (noeuds + aretes) pour le frontend."""
    return {
        "nodes": [{"id": node, **attrs} for node, attrs in graph.nodes(data=True)],
        "edges": [
            {"source": src, "target": dst, **attrs}
            for src, dst, attrs in graph.edges(data=True)
        ],
    }


def run_pipeline(collector_path=COLLECTOR_FILE):
    """Lance toute la chaine et enregistre le resultat dans analysis_result.json."""
    collector_path = Path(collector_path)
    with open(collector_path, encoding="utf-8") as f:
        data = json.load(f)

    # 1. Vulnerabilites (CVE/CVSS via NVD, avec cache)
    vuln_report = analyze_infrastructure(collector_path)

    # 2. Graphe d'attaque
    graph = build_graph(data)

    # 3. Chemins d'attaque vers chaque cible d'interet
    attack_paths = []
    for target, reason in find_candidate_targets(graph):
        paths = find_attack_paths(graph, target=target)
        attack_paths.append({
            "target": target,
            "reason": reason,
            "path_count": len(paths),
            "paths": paths,
        })

    result = {
        "analysis_date": datetime.now().isoformat(timespec="seconds"),
        "scan_date": data.get("scan_date"),
        "vulnerabilities": vuln_report,
        "attack_graph": graph_to_dict(graph),
        "attack_paths": attack_paths,
    }

    DATA_DIR.mkdir(exist_ok=True)
    with open(ANALYSIS_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    return result


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else COLLECTOR_FILE
    result = run_pipeline(path)
    graph = result["attack_graph"]
    print(f"Graphe : {len(graph['nodes'])} noeuds, {len(graph['edges'])} aretes")
    for t in result["attack_paths"]:
        print(f"[{t['reason']}] {t['target']} : {t['path_count']} chemin(s)")
        for p in t["paths"]:
            print("    " + " -> ".join(p["path"]))
    print(f"Resultat enregistre : {ANALYSIS_FILE}")