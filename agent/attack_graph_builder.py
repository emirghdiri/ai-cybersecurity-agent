"""
Construit le graphe d'attaque (NetworkX) a partir de collector_output.json.
Un noeud par service/conteneur (+ "kali"), une arete par relation detectee
(collecteur + scan Nmap). Le graphe est ensuite utilise par attack_path_finder.py.
"""
import json
import networkx as nx

COLLECTOR_OUTPUT = "collector_output.json"


def load_collector_output(path=COLLECTOR_OUTPUT):
    with open(path) as f:
        return json.load(f)


def build_graph(data):
    graph = nx.DiGraph()  # dirige : kali -> api a un sens, pas l'inverse

    graph.add_node("kali", role="attacker")

    host = data["hosts"][0]
    for svc in host["services"]:
        node_id = svc.get("container") or svc["name"]
        graph.add_node(
            node_id,
            port=svc["port"],
            name=svc["name"],
            version=svc.get("version"),
            exposed_externally=svc.get("exposed_externally", False),
        )

    for rel in data["relations"]:
        for node_id in (rel["source"], rel["target"]):
            if node_id not in graph:
                # Noeud reference seulement par une relation (ex. lab-db, qui n'a
                # aucun port publie donc n'apparait jamais dans "services") :
                # on le considere non expose par defaut.
                graph.add_node(node_id, exposed_externally=False)

        graph.add_edge(
            rel["source"],
            rel["target"],
            port=rel.get("port"),
            via=rel.get("via", "network"),
        )

    return graph

def main():
    data = load_collector_output()
    graph = build_graph(data)
    print(f"Graphe construit : {graph.number_of_nodes()} noeuds, {graph.number_of_edges()} aretes.")
    print("Noeuds :", list(graph.nodes))
    print("Aretes :", list(graph.edges(data=True)))
    return graph


if __name__ == "__main__":
    main()