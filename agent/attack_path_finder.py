"""
Cherche tous les chemins d'attaque possibles entre kali et chaque actif d'interet
detecte automatiquement a partir de FAITS STRUCTURELS (pas de jugement de risque -
ca, c'est le role du Risk Analyzer, qui combinera ces faits avec les CVE/CVSS).

Un service est retenu comme cible d'interet si :
  - "not_exposed" : il n'a aucun port publie vers l'exterieur
  - "pivot"       : il est expose ET relie a un service non expose
"""
import networkx as nx

from attack_graph_builder import load_collector_output, build_graph


def find_candidate_targets(graph):
    candidates = []
    for node, attrs in graph.nodes(data=True):
        if node == "kali":
            continue
        if attrs.get("exposed_externally") is False:
            candidates.append((node, "not_exposed"))
        elif any(
            graph.nodes[succ].get("exposed_externally") is False
            for succ in graph.successors(node)
        ):
            candidates.append((node, "pivot"))
    return candidates


def describe_hop(graph, source, target):
    edge = graph.get_edge_data(source, target)
    port = edge.get("port")
    via = edge.get("via", "network")

    if source == "kali":
        port_txt = f" (port {port})" if port else ""
        return f"{target} est directement accessible depuis l'exterieur{port_txt}."
    if via and via.startswith("docker"):
        return f"{source} est egalement connecte au reseau interne, ce qui lui permet d'atteindre {target}."
    return f"{source} peut ensuite atteindre {target}."


def describe_path(graph, path):
    hops = [describe_hop(graph, path[i], path[i + 1]) for i in range(len(path) - 1)]
    return " ".join(hops)


def find_attack_paths(graph, source="kali", target=None):
    if target not in graph:
        return []
    results = []
    for path in nx.all_simple_paths(graph, source=source, target=target):
        results.append({
            "path": path,
            "length": len(path) - 1,
            "description": describe_path(graph, path),
        })
    return results


def main():
    data = load_collector_output()
    graph = build_graph(data)

    targets = find_candidate_targets(graph)
    print(f"{len(targets)} cible(s) d'interet detectee(s) :\n")

    for target, reason in targets:
        paths = find_attack_paths(graph, target=target)
        print(f"[{reason}] {target} — {len(paths)} chemin(s)")
        for p in paths:
            print("   ", " -> ".join(p["path"]))
            print("     ", p["description"])
        print()


if __name__ == "__main__":
    main()