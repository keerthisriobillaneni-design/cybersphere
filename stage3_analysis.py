
import json
import os
import networkx as nx
import matplotlib.pyplot as plt

DATA_FILE = "enterprise-attack.json"
OUTPUT_DIR = "stage3_output"


def main():
    if not os.path.exists(DATA_FILE):
        print(f"ERROR: {DATA_FILE} was not found.")
        print("Download the dataset into the project folder first.")
        return

    with open(DATA_FILE, "r", encoding="utf-8") as file:
        dataset = json.load(file)

    objects = dataset.get("objects", [])
    graph = nx.DiGraph()

    # Index ATT&CK objects by their STIX IDs.
    entities = {}

    for obj in objects:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        if obj.get("type") == "relationship":
            continue

        stix_id = obj.get("id")
        name = obj.get("name")

        if not stix_id or not name:
            continue

        entities[stix_id] = obj
        graph.add_node(
            stix_id,
            name=name,
            entity_type=obj.get("type", "unknown")
        )

    # Connect entities using ATT&CK relationship records.
    for obj in objects:
        if obj.get("type") != "relationship":
            continue

        source_id = obj.get("source_ref")
        target_id = obj.get("target_ref")
        relation = obj.get("relationship_type", "related-to")

        if source_id in entities and target_id in entities:
            graph.add_edge(
                source_id,
                target_id,
                relationship=relation
            )

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Count entity types.
    type_counts = {}
    for _, data in graph.nodes(data=True):
        entity_type = data["entity_type"]
        type_counts[entity_type] = type_counts.get(entity_type, 0) + 1

    print("\n=== CyberSphere Stage 3 ===")
    print("Graph nodes:", graph.number_of_nodes())
    print("Graph relationships:", graph.number_of_edges())

    print("\nEntity counts:")
    for entity_type, count in sorted(type_counts.items()):
        print(f"{entity_type}: {count}")

    # Find groups and their connected techniques.
    print("\n=== Threat Group Connections ===")
    group_count = 0

    for node, data in graph.nodes(data=True):
        if data["entity_type"] != "intrusion-set":
            continue

        group_count += 1
        print(f"\nGroup: {data['name']}")

        connections = 0
        for neighbor in graph.successors(node):
            neighbor_data = graph.nodes[neighbor]
            relation = graph.edges[node, neighbor]["relationship"]

            print(
                f"  --{relation}--> "
                f"{neighbor_data['name']} "
                f"[{neighbor_data['entity_type']}]"
            )
            connections += 1

            if connections >= 10:
                print("  ... additional connections omitted")
                break

    print(f"\nThreat groups inspected: {group_count}")

    # Export graph structure for later use in the dashboard.
    graph_file = os.path.join(OUTPUT_DIR, "attack_graph.graphml")
    nx.write_graphml(graph, graph_file)

    # Save a readable summary.
    summary_file = os.path.join(OUTPUT_DIR, "summary.txt")
    with open(summary_file, "w", encoding="utf-8") as file:
        file.write("CyberSphere Stage 3 Summary\n")
        file.write(f"Nodes: {graph.number_of_nodes()}\n")
        file.write(f"Relationships: {graph.number_of_edges()}\n\n")

        for entity_type, count in sorted(type_counts.items()):
            file.write(f"{entity_type}: {count}\n")

    # Draw a small sample so large datasets remain readable.
    if graph.number_of_nodes() > 0:
        sample_nodes = list(graph.nodes())[:60]
        sample_graph = graph.subgraph(sample_nodes).copy()

        plt.figure(figsize=(14, 9))
        positions = nx.spring_layout(sample_graph, seed=42)

        labels = {
            node: data["name"][:25]
            for node, data in sample_graph.nodes(data=True)
        }

        nx.draw_networkx(
            sample_graph,
            positions,
            labels=labels,
            node_size=650,
            font_size=7,
            arrows=True,
            with_labels=True
        )

        plt.title("CyberSphere: ATT&CK Relationship Graph")
        plt.axis("off")

        image_file = os.path.join(
            OUTPUT_DIR, "attack_graph.png"
        )
        plt.tight_layout()
        plt.savefig(image_file, dpi=160)
        plt.close()

        print("\nGraph image:", image_file)

    print("GraphML export:", graph_file)
    print("Summary:", summary_file)
    print("\nStage 3 analysis completed.")


if __name__ == "__main__":
    main()