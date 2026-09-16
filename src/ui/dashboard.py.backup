import html
import time
from typing import Dict, Tuple

import networkx as nx
import streamlit as st

from shadowcut_controller import ShadowCutController


st.set_page_config(page_title="ShadowCut Security Console", page_icon="SC", layout="wide", initial_sidebar_state="collapsed")

CSS = """
<style>
:root { --bg:#07111f; --panel:#0d1b2a; --panel2:#10253a; --text:#e6edf5; --muted:#91a4b7; --line:#27415c; --cyan:#43c6ff; --red:#ff5c6c; --green:#51d88a; --amber:#f3bf52; }
.stApp { background: var(--bg); color: var(--text); }
.block-container { padding-top: 1.2rem; max-width: 1500px; }
.sc-header { display:flex; justify-content:space-between; align-items:center; padding:14px 18px; border:1px solid var(--line); border-radius:16px; background:linear-gradient(135deg,#0d1b2a,#0b1724); margin-bottom:14px; }
.sc-title { font-size:24px; font-weight:700; letter-spacing:.02em; }
.sc-sub { color:var(--muted); font-size:13px; margin-top:4px; }
.status { display:flex; align-items:center; gap:8px; color:var(--green); font-weight:600; font-size:13px; }
.dot { width:9px; height:9px; background:var(--green); border-radius:50%; box-shadow:0 0 12px rgba(81,216,138,.6); }
.network { border:1px solid var(--line); border-radius:16px; background:radial-gradient(circle at 50% 45%,#102438 0,#091522 60%,#07111f 100%); padding:12px; }
.phase { border:1px solid var(--line); border-radius:14px; padding:14px; background:var(--panel); margin-bottom:10px; }
.phase-title { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.12em; }
.phase-value { margin-top:5px; font-size:20px; font-weight:700; }
.metric { border:1px solid var(--line); border-radius:12px; padding:12px; background:var(--panel); }
.metric-label { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.08em; }
.metric-value { font-size:22px; font-weight:700; margin-top:4px; }
.success { color:var(--green); }
.warn { color:var(--amber); }
.fail { color:var(--red); }
.cut-chip { display:inline-block; padding:6px 8px; border:1px solid #7f3641; border-radius:8px; margin:3px; background:#24131a; color:#ff9aa5; font-family:monospace; font-size:11px; }
.small { font-size:12px; color:var(--muted); }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


def build_demo_graph() -> nx.DiGraph:
    g = nx.DiGraph()

    # Normal enterprise topology.
    for i in range(28):
        g.add_node(f"PC-{i+1:02d}", kind="pc")
    for name in ["WEB-01", "APP-01", "DB-01", "ID-01", "FIN-01", "FILE-01", "VAULT"]:
        g.add_node(name, kind="server")
    g.nodes["VAULT"]["kind"] = "critical"

    edges = [
        ("PC-01", "WEB-01"), ("PC-02", "WEB-01"), ("PC-03", "WEB-01"),
        ("PC-04", "APP-01"), ("PC-05", "APP-01"), ("PC-06", "APP-01"),
        ("WEB-01", "APP-01"), ("APP-01", "DB-01"), ("APP-01", "ID-01"),
        ("DB-01", "FIN-01"), ("FIN-01", "VAULT"), ("ID-01", "FILE-01"),
        ("FILE-01", "VAULT"), ("PC-10", "FILE-01"), ("PC-11", "FIN-01"),
        ("PC-12", "DB-01"), ("PC-13", "ID-01"), ("PC-14", "WEB-01"),
    ]
    for u, v in edges:
        g.add_edge(u, v, cost=1.0)

    # Incident paths. The bypass is deliberately longer than the initial k=2 view.
    attack = ["PC-07", "WEB-01", "APP-01", "DB-01", "FIN-01", "VAULT"]
    for u, v, c in zip(attack[:-1], attack[1:], [1.0, 1.0, 2.0, 3.0, 5.0]):
        g.add_edge(u, v, cost=c, attack=True)

    bypass = ["PC-07", "PC-08", "FILE-01", "VAULT"]
    for u, v, c in zip(bypass[:-1], bypass[1:], [1.0, 2.0, 6.0]):
        g.add_edge(u, v, cost=c, bypass=True)

    # Secondary protected assets to exercise greedy selection.
    g.nodes["FIN-01"]["kind"] = "critical"
    g.nodes["ID-01"]["kind"] = "critical"
    g.add_edge("PC-07", "ID-01", cost=2.0, attack=True)
    return g


def node_position(node: str, graph: nx.DiGraph) -> Tuple[float, float]:
    pos = graph.graph.get("ui_pos", {})
    if node in pos:
        return pos[node]
    return (50.0, 50.0)


def build_svg(graph: nx.DiGraph, highlight_nodes=None, cut_edges=None, attacker=None, fade_outside=False, height=560) -> str:
    highlight_nodes = set(highlight_nodes or [])
    cut_edges = set(cut_edges or [])
    attacker = attacker or ""

    positions = graph.graph["ui_pos"]
    width = 1100
    edge_svg = []
    node_svg = []

    for u, v, data in graph.edges(data=True):
        x1, y1 = positions[u]
        x2, y2 = positions[v]
        active = u in highlight_nodes and v in highlight_nodes
        is_cut = (u, v) in cut_edges
        stroke = "#ff5c6c" if is_cut else ("#43c6ff" if active else "#29435f")
        opacity = "1" if active or is_cut else ("0.16" if fade_outside else "0.50")
        dash = "6 5" if is_cut else "none"
        edge_svg.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke}" '
            f'stroke-width="{3 if is_cut else 1.4}" opacity="{opacity}" stroke-dasharray="{dash}"/>'
        )

    for node in graph.nodes:
        x, y = positions[node]
        kind = graph.nodes[node].get("kind", "pc")
        active = node in highlight_nodes
        if node == attacker:
            fill, stroke = "#4d1219", "#ff5c6c"
        elif kind == "critical":
            fill, stroke = "#173d2e", "#51d88a"
        elif kind == "server":
            fill, stroke = "#183451", "#43c6ff"
        else:
            fill, stroke = "#122131", "#5f7891"
        opacity = "1" if active or node == attacker or kind == "critical" else ("0.22" if fade_outside else "0.85")
        r = 16 if kind != "pc" else 12
        label = html.escape(node)
        node_svg.append(
            f'<g opacity="{opacity}"><circle cx="{x}" cy="{y}" r="{r}" fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
            f'<text x="{x}" y="{y+29}" fill="#dfe9f2" font-size="10" text-anchor="middle">{label}</text></g>'
        )

    return f'''<div class="network"><svg viewBox="0 0 {width} {height}" width="100%" height="{height}" preserveAspectRatio="xMidYMid meet">
        <defs><filter id="glow"><feGaussianBlur stdDeviation="4" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
        {''.join(edge_svg)}{''.join(node_svg)}
    </svg></div>'''


def position_demo_graph(g: nx.DiGraph) -> None:
    positions: Dict[str, Tuple[float, float]] = {}
    pcs = [n for n in g.nodes if n.startswith("PC-")]
    for idx, node in enumerate(pcs):
        row, col = divmod(idx, 7)
        positions[node] = (75 + col * 92, 70 + row * 72)
    positions.update({
        "WEB-01": (340, 110), "APP-01": (500, 180), "DB-01": (660, 260),
        "ID-01": (620, 120), "FILE-01": (790, 120), "FIN-01": (800, 280),
        "VAULT": (980, 235),
    })
    g.graph["ui_pos"] = positions


graph = build_demo_graph()
position_demo_graph(graph)
controller = ShadowCutController(graph)

st.markdown('''<div class="sc-header"><div><div class="sc-title">ShadowCut Security Console</div><div class="sc-sub">Locality-aware lateral movement containment and verification</div></div><div class="status"><span class="dot"></span>SYSTEM ONLINE</div></div>''', unsafe_allow_html=True)

if "incident_run" not in st.session_state:
    st.session_state.incident_run = False

left, right = st.columns([3.2, 1.2])
with left:
    st.subheader("Enterprise Network")
    network_placeholder = st.empty()
    network_placeholder.markdown(build_svg(graph), unsafe_allow_html=True)
with right:
    st.markdown('<div class="phase"><div class="phase-title">Network State</div><div class="phase-value">28 PCs + 7 servers</div><div class="small">35 nodes / live simulated topology</div></div>', unsafe_allow_html=True)
    st.markdown('<div class="phase"><div class="phase-title">Protected Assets</div><div class="phase-value">3</div><div class="small">VAULT, FIN-01, ID-01</div></div>', unsafe_allow_html=True)
    budget = st.slider("Disruption budget", 1.0, 20.0, 10.0, 1.0)
    initial_k = st.slider("Initial radius", 1, 4, 2)
    max_k = st.slider("Maximum radius", initial_k, 6, max(4, initial_k))
    run = st.button("Run ShadowCut", type="primary", use_container_width=True)

if run:
    incident = ["PC-07", "WEB-01", "APP-01", "DB-01", "FIN-01", "VAULT"]
    phases = st.container()

    phases.info("Detecting suspicious lateral movement...")
    network_placeholder.markdown(build_svg(graph, highlight_nodes=set(incident), attacker="PC-07"), unsafe_allow_html=True)
    time.sleep(0.7)

    phases.info(f"Incident detected: PC-07 can reach VAULT. Initial locality boundary: k={initial_k}.")
    local_nodes = set(nx.ego_graph(graph, "PC-07", radius=initial_k, undirected=False).nodes)
    network_placeholder.markdown(build_svg(graph, highlight_nodes=local_nodes, attacker="PC-07", fade_outside=True), unsafe_allow_html=True)
    time.sleep(0.7)

    phases.info("Running maximum-flow / minimum-cut optimization on the incident neighborhood...")
    result = controller.analyze_incident(
        attacker="PC-07",
        targets=["VAULT", "FIN-01", "ID-01"],
        budget=budget,
        initial_radius=initial_k,
        max_radius=max_k,
        attack_path=incident,
    )
    time.sleep(0.7)

    if result.expanded:
        phases.warning(f"Local solution required expansion: k={result.initial_radius} -> k={result.final_radius}. Validating against the global graph...")
        time.sleep(0.8)

    if result.global_containment:
        phases.success("Global validation passed. Containment is verified on the full graph.")
    else:
        phases.error(result.validation_message)

    final_local = set(nx.ego_graph(graph, "PC-07", radius=result.final_radius, undirected=False).nodes)
    network_placeholder.markdown(build_svg(graph, highlight_nodes=final_local, cut_edges=set(result.selected_edges), attacker="PC-07", fade_outside=True), unsafe_allow_html=True)

    st.markdown("### Decision")
    cols = st.columns(5)
    metrics = [
        ("Final k", str(result.final_radius)),
        ("Locality", f"{result.locality_vertex_ratio*100:.1f}% nodes"),
        ("Max flow", f"{result.max_flow:.1f}" if result.max_flow is not None else "N/A"),
        ("Cut cost", f"{result.disruption_cost:.1f} / {budget:.1f}"),
        ("Validation", "PASSED" if result.global_containment else "FAILED"),
    ]
    for c, (label, value) in zip(cols, metrics):
        c.markdown(f'<div class="metric"><div class="metric-label">{label}</div><div class="metric-value {"success" if label=="Validation" and result.global_containment else ""}">{value}</div></div>', unsafe_allow_html=True)

    st.markdown("### Greedy containment selection")
    if result.candidate_history:
        history = result.candidate_history[-1].get("greedy", [])
        if history:
            for item in history:
                st.markdown(f"**{item['target']}** — incremental cost {item['incremental_cost']:.1f}, cumulative cost {item['total_cost']:.1f} — selected")
        else:
            st.markdown('<span class="small">No candidate could be selected within the configured budget.</span>', unsafe_allow_html=True)

    if result.selected_edges:
        chips = "".join(f'<span class="cut-chip">{html.escape(u)} -&gt; {html.escape(v)}</span>' for u, v in result.selected_edges)
        st.markdown(f"**Connections to sever:** {chips}", unsafe_allow_html=True)
    st.session_state.incident_run = True
