
import csv
import os
import re
import networkx as nx

GRAPH_FILE = os.path.join(
    "stage3_output", "attack_graph.graphml"
)
REPORT_FILE = "threat_report.txt"
OUTPUT_DIR = "stage5_output"


def split_sentences(text):
    """Simple sentence splitter for the prototype."""
    return [
        sentence.strip()
        for sentence in re.split(r"(?<=[.!?])\s+", text)
        if sentence.strip()
    ]


def main():
    if not os.path.exists(GRAPH_FILE):
        print("ERROR: Stage 3 GraphML file not found.")
        print("Run: python stage3_analysis.py")
        return

    if not os.path.exists(REPORT_FILE):
        print(f"ERROR: {REPORT_FILE} was not found.")
        return

    graph = nx.read_graphml(GRAPH_FILE)

    # Build a dictionary of known ATT&CK entity names.
    entities = []

    for node, data in graph.nodes(data=True):
        name = data.get("name", "")
        if len(name.strip()) >= 3:
            entities.append({
                "id": node,
                "name": name.strip(),
                "type": data.get("entity_type", "unknown")
            })

    # Prefer longer names to reduce overlapping matches.
    entities.sort(
        key=lambda item: len(item["name"]),
        reverse=True
    )

    with open(
        REPORT_FILE, "r", encoding="utf-8"
    ) as file:
        report = file.read()

    sentences = split_sentences(report)
    entity_rows = []
    relationship_rows = []

    for sentence_number, sentence in enumerate(
        sentences, start=1
    ):
        matched = []
        occupied_spans = []

        # Find known names without matching inside larger words.
        for entity in entities:
            pattern = re.compile(
                r"(?<!\w)" + re.escape(entity["name"])
                + r"(?!\w)",
                re.IGNORECASE
            )

            match = pattern.search(sentence)
            if not match:
                continue

            span = match.span()

            # Avoid overlapping matches where possible.
            if any(
                span[0] < end and start < span[1]
                for start, end in occupied_spans
            ):
                continue

            occupied_spans.append(span)
            matched.append(entity)

            entity_rows.append({
                "sentence_number": sentence_number,
                "entity_name": entity["name"],
                "entity_type": entity["type"],
                "entity_id": entity["id"],
                "evidence_sentence": sentence
            })

        # Co-occurrence is only a candidate relationship,
        # not proof that a relationship exists.
        for i, first in enumerate(matched):
            for second in matched[i + 1:]:
                relationship_rows.append({
                    "sentence_number": sentence_number,
                    "entity_1": first["name"],
                    "entity_1_type": first["type"],
                    "entity_2": second["name"],
                    "entity_2_type": second["type"],
                    "candidate_basis": "same_sentence",
                    "evidence_sentence": sentence,
                    "review_status": "needs_review"
                })

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    entity_path = os.path.join(
        OUTPUT_DIR, "extracted_entities.csv"
    )
    relationship_path = os.path.join(
        OUTPUT_DIR, "candidate_relationships.csv"
    )

    with open(
        entity_path, "w", newline="", encoding="utf-8"
    ) as file:
        columns = [
            "sentence_number", "entity_name", "entity_type",
            "entity_id", "evidence_sentence"
        ]
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(entity_rows)

    with open(
        relationship_path, "w", newline="", encoding="utf-8"
    ) as file:
        columns = [
            "sentence_number", "entity_1", "entity_1_type",
            "entity_2", "entity_2_type", "candidate_basis",
            "evidence_sentence", "review_status"
        ]
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(relationship_rows)

    print("\n=== CyberSphere Stage 5 ===")
    print("Sentences processed:", len(sentences))
    print("Entity mentions found:", len(entity_rows))
    print("Candidate relationships:", len(relationship_rows))
    print("Entity output:", entity_path)
    print("Relationship output:", relationship_path)
    print("\nCandidate relationships require manual verification.")


if __name__ == "__main__":
    main()