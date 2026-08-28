import streamlit as st
import networkx as nx
import matplotlib.pyplot as plt
import time
import sys
import os

# Ensure Python can find our backend modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from graph.graph_state import EnterpriseGraph
from containment.containment_engine import ContainmentEngine

# --- 1. SYSTEM INITIALIZATION & CACHING ---
@st.cache_resource
def load_enterprise_system():
    """Initializes the backend and generates the 1000-node background noise only once."""
    sys_graph = EnterpriseGraph()
    engine = ContainmentEngine()
    
    # Inject background noise
    nodes = [f"HOST_{i}" for i in range(1000)]
    import random
    for _ in range(3000):
        src, dst = random.sample(nodes, 2)
        sys_graph.ingest_auth_event(src, dst, timestamp=time.time(), disruption_cost=1.0)
        
    # Inject the specific attack path
    attacker = "COMPROMISED_PC"
    asset = "CRITICAL_VAULT"
    sys_graph.ingest_auth_event(attacker, "PIVOT_1", timestamp=time.time(), disruption_cost=1.0)
    sys_graph.ingest_auth_event("PIVOT_1", asset, timestamp=time.time(), disruption_cost=5.0)
    sys_graph.ingest_auth_event(attacker, "PIVOT_2", timestamp=time.time(), disruption_cost=2.0)
    sys_graph.ingest_auth_event("PIVOT_2", asset, timestamp=time.time(), disruption_cost=3.0)
    
    return sys_graph, engine

sys_graph, engine = load_enterprise_system()

# --- 2. UI LAYOUT ---
st.set_page_config(page_title="ShadowCut Security Console", layout="wide")
st.title("🛡️ ShadowCut: Real-Time Containment Console")
st.markdown("Automated lateral movement containment using dynamic graph algorithms.")

col1, col2 = st.columns([1, 2])

with col1:
    st.header("Threat Parameters")
    alerted_host = st.text_input("Suspected Host", value="COMPROMISED_PC")
    critical_asset = st.text_input("Target Asset", value="CRITICAL_VAULT")
    budget = st.slider("Disruption Budget", min_value=1.0, max_value=20.0, value=5.0)
    k_radius = st.number_input("Extraction Radius (k-hops)", min_value=1, max_value=5, value=2)
    
    analyze_btn = st.button("Trigger ShadowCut Analysis")

# --- 3. CONTAINMENT EXECUTION ---
if analyze_btn:
    with col2:
        st.header("Containment Execution")
        
        start_extract = time.perf_counter()
        subgraph = sys_graph.extract_neighborhood(alerted_host, radius=k_radius)
        extract_time = (time.perf_counter() - start_extract) * 1000
        
        if not subgraph:
            st.error("Host not found in global graph state.")
        else:
            # Run Algorithm
            start_calc = time.perf_counter()
            cost, cuts, exposed = engine.compute_budgeted_containment(
                subgraph, alerted_host, [critical_asset], budget
            )
            calc_time = (time.perf_counter() - start_calc) * 1000
            
            # --- METRICS DISPLAY ---
            m1, m2, m3 = st.columns(3)
            m1.metric("Extraction Latency", f"{extract_time:.2f} ms")
            m2.metric("Min-Cut Latency", f"{calc_time:.2f} ms")
            m3.metric("Disruption Cost", f"{cost:.1f} / {budget:.1f}")
            
            if exposed:
                st.error(f"Budget Exhausted! {exposed} remains exposed.")
            else:
                st.success("Target successfully isolated within budget.")
                
            st.warning(f"Recommended Connections to Sever: {cuts}")
            
            # --- GRAPH VISUALIZATION ---
            st.subheader("Bounded Threat Neighborhood (Visualized)")
            fig, ax = plt.subplots(figsize=(8, 5))
            
            # Color mapping
            node_colors = []
            for node in subgraph.nodes():
                if node == alerted_host: node_colors.append('red')
                elif node == critical_asset: node_colors.append('green')
                else: node_colors.append('lightblue')
                
            edge_colors = ['red' if e in cuts else 'gray' for e in subgraph.edges()]
            edge_widths = [2 if e in cuts else 1 for e in subgraph.edges()]
            
            pos = nx.spring_layout(subgraph, seed=42)
            nx.draw(subgraph, pos, with_labels=True, node_color=node_colors, 
                    edge_color=edge_colors, width=edge_widths, ax=ax, node_size=2000, font_size=10)
            
            # Add edge weights to visualization
            edge_labels = {(u, v): f"{d['cost']}" for u, v, d in subgraph.edges(data=True)}
            nx.draw_networkx_edge_labels(subgraph, pos, edge_labels=edge_labels, ax=ax)
            
            st.pyplot(fig)
