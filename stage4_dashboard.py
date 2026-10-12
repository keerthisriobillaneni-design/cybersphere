
import os
import streamlit as st
import networkx as nx
import matplotlib.pyplot as plt

GRAPH_FILE = os.path.join(
    "stage3_output", "attack_graph.graphml"
)

st.set_page_config(
    page_title="CyberSphere",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CyberSphere")
st.subheader("Threat Intelligence and Attack Relationship Analysis")

if not os.path.exists(GRAPH_FILE):
    st.error("Graph file not found.")
    st.info(
        "Run `python stage3_analysis.py` first "
        "to generate the Stage 3 graph."
    )
    st.stop()

graph = nx.read_graphml(GRAPH_FILE)

# Dashboard metrics
col1, col2, col3 = st.columns(3)
col1.metric("Entities", graph.number_of_nodes())
col2.metric("Relationships", graph.number_of_edges())
col3.metric(
    "Entity types",
    len({
        data.get("entity_type", "unknown")
        for _, data in graph.nodes(data=True)
    })
)

st.divider()

# Search entities
nodes = list(graph.nodes(data=True))
names = {
    node: data.get("name", node)
    for node, data in nodes
}

search = st.text_input(
    "Search for a threat group, malware, or technique"
)

matches = [
    node for node, name in names.items()
    if search.lower() in name.lower()
] if search else []

if search:
    if matches:
        selected = st.selectbox(
            "Matching entities",
            matches,
            format_func=lambda node: names[node]
        )

        data = graph.nodes[selected]

        st.markdown("### Entity details")
        st.write("**Name:**", names[selected])
        st.write(
            "**Type:**",
            data.get("entity_type", "unknown")
        )

        st.markdown("### Relationships")

        connected = []

        for target in graph.successors(selected):
            connected.append((
                "Outgoing",
                graph.edges[selected, target].get(
                    "relationship", "related-to"
                ),
                names.get(target, target)
            ))

        for source in graph.predecessors(selected):
            connected.append((
                "Incoming",
                graph.edges[source, selected].get(
                    "relationship", "related-to"
                ),
                names.get(source, source)
            ))

        if connected:
            for direction, relation, entity_name in connected:
                st.write(
                    f"- {direction}: **{relation}** → "
                    f"{entity_name}"
                )
        else:
            st.info("No direct relationships found.")

        # Display a local neighborhood around the selected entity.
        neighbors = (
            set(graph.successors(selected))
            | set(graph.predecessors(selected))
        )
        neighborhood = neighbors | {selected}
        local_graph = graph.subgraph(neighborhood).copy()

        if local_graph.number_of_nodes() > 1:
            st.markdown("### Relationship graph")

            display_graph = nx.Graph(local_graph)
            positions = nx.spring_layout(
                display_graph, seed=42
            )

            labels = {
                node: names.get(node, node)[:30]
                for node in display_graph.nodes()
            }

            fig, ax = plt.subplots(figsize=(12, 7))
            nx.draw_networkx(
                display_graph,
                positions,
                labels=labels,
                node_size=1400,
                font_size=8,
                ax=ax
            )
            ax.axis("off")
            st.pyplot(fig)
            plt.close(fig)
    else:
        st.warning("No matching entities found.")

else:
    st.markdown("### Browse entities")

    entity_types = sorted({
        data.get("entity_type", "unknown")
        for _, data in nodes
    })

    chosen_types = st.multiselect(
        "Filter by entity type",
        entity_types,
        default=entity_types
    )

    filtered = [
        (node, data)
        for node, data in nodes
        if data.get("entity_type", "unknown")
        in chosen_types
    ]

    st.write(f"Showing {len(filtered)} entities")

    for node, data in filtered[:100]:
        st.write(
            f"**{data.get('name', node)}** "
            f"— {data.get('entity_type', 'unknown')}"
        )

    if len(filtered) > 100:
        st.caption("Showing the first 100 matching entities.")

st.divider()
st.caption(
    "CyberSphere academic prototype | "
    "Verify threat relationships against authoritative sources."
)