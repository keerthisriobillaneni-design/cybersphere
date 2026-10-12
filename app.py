import sys
from pathlib import Path
import streamlit as st
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
from build_graph import load_graph, analyze_actor

st.set_page_config(page_title="CyberSphere CTI Explorer", page_icon="🛡️", layout="wide")
st.title("🛡️ CyberSphere")
st.caption("Knowledge Graph for Threat Intelligence and Attack Analysis — prototype dashboard")

G = load_graph()
c1, c2, c3 = st.columns(3)
c1.metric("Entities / nodes", G.number_of_nodes())
c2.metric("Relationships / edges", G.number_of_edges())
c3.metric("Threat actors", sum(1 for _, d in G.nodes(data=True) if d.get("type") == "ThreatActor"))

st.info("This dashboard currently loads the local demo JSON dataset. Its relationships are illustrative prototype records, not verified incident findings.")

tab1, tab2, tab3 = st.tabs(["Graph overview", "Threat actor investigation", "Relationship records"])

with tab1:
    fig, ax = plt.subplots(figsize=(12, 7))
    pos = nx.spring_layout(G, seed=42, k=1.0)
    labels = {n: G.nodes[n].get("label", n) for n in G.nodes}
    nx.draw_networkx_nodes(G, pos, ax=ax, node_size=1700)
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=8, ax=ax)
    nx.draw_networkx_edges(G, pos, ax=ax, arrows=True, arrowsize=16, connectionstyle="arc3,rad=0.08")
    edge_labels = {(u, v): d.get("relation", "RELATED_TO") for u, v, k, d in G.edges(keys=True, data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7, ax=ax)
    ax.axis("off")
    st.pyplot(fig)
    plt.close(fig)

with tab2:
    actors = [n for n, d in G.nodes(data=True) if d.get("type") == "ThreatActor"]
    if actors:
        actor = st.selectbox("Choose a threat actor", actors)
        rows = analyze_actor(G, actor)
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.warning("No outgoing relationships were found for this actor.")
    else:
        st.warning("No threat actor nodes exist in the current dataset.")

with tab3:
    records = []
    for u, v, key, d in G.edges(keys=True, data=True):
        records.append({
            "source_entity": u,
            "relationship": d.get("relation", "RELATED_TO"),
            "target_entity": v,
            "confidence": d.get("confidence", 0.5),
            "source_name": d.get("source_name", "Unknown"),
            "evidence": d.get("evidence", "")
        })
    st.dataframe(pd.DataFrame(records), use_container_width=True, hide_index=True)
