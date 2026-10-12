import json
from pathlib import Path
import networkx as nx

ROOT = Path(__file__).resolve().parents[1]
DATA_FILE = ROOT / "data" / "threat_data.json"

def load_graph(path=DATA_FILE):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    graph = nx.MultiDiGraph()
    for entity in data.get("entities", []):
        graph.add_node(entity["id"], **entity)
    for rel in data.get("relationships", []):
        if rel["source"] not in graph:
            graph.add_node(rel["source"], label=rel["source"], type="Unknown")
        if rel["target"] not in graph:
            graph.add_node(rel["target"], label=rel["target"], type="Unknown")
        graph.add_edge(
            rel["source"], rel["target"],
            relation=rel.get("type", "RELATED_TO"),
            confidence=float(rel.get("confidence", 0.5)),
            source_name=rel.get("source_name", "Unknown"),
            evidence=rel.get("evidence", "")
        )
    return graph

def analyze_actor(graph, actor_id):
    if actor_id not in graph:
        return []
    rows = []
    for _, target, key, attrs in graph.out_edges(actor_id, keys=True, data=True):
        rows.append({
            "actor": actor_id,
            "relationship": attrs.get("relation", "RELATED_TO"),
            "connected_entity": target,
            "entity_type": graph.nodes[target].get("type", "Unknown"),
            "confidence": attrs.get("confidence", 0.5),
            "source": attrs.get("source_name", "Unknown"),
            "evidence": attrs.get("evidence", "")
        })
    return rows

if __name__ == "__main__":
    G = load_graph()
    print(f"CyberSphere graph loaded: {G.number_of_nodes()} nodes, {G.number_of_edges()} relationships")
    print("\nAPT29 connected entities:")
    for row in analyze_actor(G, "APT29"):
        print(f"- {row['relationship']} -> {row['connected_entity']} "
              f"(type={row['entity_type']}, confidence={row['confidence']:.2f})")
