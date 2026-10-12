
import csv
import os
import networkx as nx

GRAPH_FILE = os.path.join(
    "stage3_output", "attack_graph.graphml"
)
CANDIDATE_FILE = os.path.join(
    "stage5_output", "candidate_relationships.csv"
)
OUTPUT_DIR = "stage6_output"

RELATION_TYPES = [
    "uses",
    "exploits",
    "targets",
    "communicates-with",
    "other"
]


def main():
    if not os.path.exists(GRAPH_FILE):
        print("Missing Stage 3 graph:", GRAPH_FILE)
        return

    if not os.path.exists(CANDIDATE_FILE):
        print("Missing Stage 5 candidates:", CANDIDATE_FILE)
        print("Run python stage5_nlp.py first.")
        return

    graph = nx.read_graphml(GRAPH_FILE)

    with open(
        CANDIDATE_FILE, newline="", encoding="utf-8"
    ) as file:
        candidates = list(csv.DictReader(file))

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    review_file = os.path.join(
        OUTPUT_DIR, "relationship_reviews.csv"
    )
    verified_graph_file = os.path.join(
        OUTPUT_DIR, "verified_graph.graphml"
    )

    review_columns = [
        "entity_1",
        "entity_2",
        "relationship_type",
        "decision",
        "confidence",
        "evidence_sentence",
        "review_note"
    ]

    # Resume previously reviewed candidates.
    reviews = []
    reviewed_keys = set()

    if os.path.exists(review_file):
        with open(
            review_file, newline="", encoding="utf-8"
        ) as file:
            reviews = list(csv.DictReader(file))

        reviewed_keys = {
            (
                row["entity_1"],
                row["entity_2"],
                row["evidence_sentence"]
            )
            for row in reviews
        }

    for index, candidate in enumerate(candidates, start=1):
        entity_1 = candidate["entity_1"]
        entity_2 = candidate["entity_2"]
        evidence = candidate["evidence_sentence"]

        key = (entity_1, entity_2, evidence)
        if key in reviewed_keys:
            continue

        print("\n" + "=" * 65)
        print(f"Candidate {index} of {len(candidates)}")
        print(f"Entity 1: {entity_1}")
        print(f"Entity 2: {entity_2}")
        print("Evidence:", evidence)
        print(
            "\nThese entities co-occur in a sentence. "
            "That alone does not prove a relationship."
        )

        
           try:
    decision = input(
        "Decision: [a]pprove, [r]eject, [s]kip, [q]uit: "
    ).strip().lower()
except (EOFError, KeyboardInterrupt):
    print("\nInput interrupted. Exiting review safely.")
    break
        if decision == "q":
            break

        if decision == "s":
            continue

        relationship_type = ""
        confidence = ""
        note = input("Review note (optional): ").strip()

        if decision == "a":
            print("Relationship types:")
            for number, relation in enumerate(
                RELATION_TYPES, start=1
            ):
                print(f"{number}. {relation}")

            while True:
                choice = input(
                    "Choose type number: "
                ).strip()
                if choice in {"1", "2", "3", "4", "5"}:
                    relationship_type = RELATION_TYPES[
                        int(choice) - 1
                    ]
                    break

            while True:
                value = input(
                    "Evidence confidence (0-100): "
                ).strip()
                try:
                    number = int(value)
                    if 0 <= number <= 100:
                        confidence = number
                        break
                except ValueError:
                    pass
                print("Enter a whole number from 0 to 100.")

        review = {
            "entity_1": entity_1,
            "entity_2": entity_2,
            "relationship_type": relationship_type,
            "decision": (
                "approved" if decision == "a" else "rejected"
            ),
            "confidence": confidence,
            "evidence_sentence": evidence,
            "review_note": note
        }

        reviews.append(review)
        reviewed_keys.add(key)

        # Save after each review so progress is not lost.
        with open(
            review_file, "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(
                file, fieldnames=review_columns
            )
            writer.writeheader()
            writer.writerows(reviews)

    # Build a separate graph; preserve the Stage 3 graph.
    verified_graph = graph.copy()

    for review in reviews:
        if review["decision"] != "approved":
            continue

        first = review["entity_1"]
        second = review["entity_2"]

        # Resolve graph nodes by their stored display names.
        name_to_node = {
            data.get("name", node): node
            for node, data in verified_graph.nodes(data=True)
        }

        first_node = name_to_node.get(first)
        second_node = name_to_node.get(second)

        # Do not silently invent entities absent from the base graph.
        if first_node is None or second_node is None:
            continue

        verified_graph.add_edge(
            first_node,
            second_node,
            relationship=review["relationship_type"],
            evidence=review["evidence_sentence"],
            confidence=str(review["confidence"]),
            source="analyst_review"
        )

    nx.write_graphml(verified_graph, verified_graph_file)

    print("\nStage 6 review finished.")
    print("Review records:", review_file)
    print("Verified graph:", verified_graph_file)
    print(
        "Approved records:",
        sum(r["decision"] == "approved" for r in reviews)
    )
    print(
        "Rejected records:",
        sum(r["decision"] == "rejected" for r in reviews)
    )
    print(
        "\nReview confidence is a human assessment, "
        "not a calibrated probability."
    )


if __name__ == "__main__":
    main()