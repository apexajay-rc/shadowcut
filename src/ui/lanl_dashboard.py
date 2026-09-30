"""
LANL Evidence Console for ShadowCut.

This is intentionally a separate Streamlit entry point so the existing
controlled demo remains untouched for the project presentation.

Run:
    PYTHONPATH=./src streamlit run src/ui/lanl_dashboard.py
"""

from __future__ import annotations

import html
import time
from pathlib import Path
from typing import Iterable, Optional, Set, Tuple

import networkx as nx
import streamlit as st

from ingestion.lanl_snapshot import LANLSnapshot, build_lanl_snapshot
from shadowcut_controller import ShadowCutController


st.set_page_config(
    page_title="ShadowCut — LANL Evidence Console",
    page_icon="SC",
    layout="wide",
    initial_sidebar_state="expanded",
)


st.markdown(
    """
    <style>
    .stApp { background: #07111f; color: #e6edf5; }
    .block-container { max-width: 1500px; padding-top: 1rem; }
    .panel {
        border: 1px solid #27415c;
        border-radius: 14px;
        padding: 14px;
        background: #0d1b2a;
        margin-bottom: 10px;
    }
    .metric {
        border: 1px solid #27415c;
        border-radius: 12px;
        padding: 12px;
        background: #0d1b2a;
    }
    .muted { color: #91a4b7; font-size: 12px; }
    .success { color: #51d88a; }
    .fail { color: #ff5c6c; }
    .chip {
        display: inline-block;
        padding: 5px 8px;
        margin: 3px;
        border: 1px solid #7f3641;
        border-radius: 8px;
        color: #ff9aa5;
        background: #24131a;
        font-family: monospace;
        font-size: 11px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def _position_graph(graph: nx.DiGraph) -> None:
    if graph.number_of_nodes() == 0:
        graph.graph["ui_pos"] = {}
        return

    # Layout only the display subgraph, not the potentially huge full LANL graph.
    positions = nx.spring_layout(graph, seed=7)
    xs = [p[0] for p in positions.values()]
    ys = [p[1] for p in positions.values()]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)

    def scale(value: float, lo: float, hi: float, start: float, end: float) -> float:
        if hi == lo:
            return (start + end) / 2.0
        return start + (value - lo) / (hi - lo) * (end - start)

    graph.graph["ui_pos"] = {
        node: (
            scale(x, min_x, max_x, 60, 1040),
            scale(y, min_y, max_y, 60, 500),
        )
        for node, (x, y) in positions.items()
    }


def _display_graph(snapshot: LANLSnapshot, radius: int = 3) -> nx.DiGraph:
    attacker = snapshot.incident.attacker
    display = nx.ego_graph(
        snapshot.graph.G,
        attacker,
        radius=radius,
        undirected=False,
    ).copy()
    if snapshot.incident.target in snapshot.graph.G:
        display.add_node(snapshot.incident.target)
    _position_graph(display)
    return display


def _build_svg(
    graph: nx.DiGraph,
    *,
    highlight_nodes: Optional[Set[str]] = None,
    attacker: Optional[str] = None,
    target: Optional[str] = None,
    cut_edges: Optional[Set[Tuple[str, str]]] = None,
    fade_outside: bool = False,
) -> str:
    highlight_nodes = set(highlight_nodes or [])
    cut_edges = set(cut_edges or [])
    positions = graph.graph.get("ui_pos", {})
    width, height = 1100, 560

    edge_parts = []
    for u, v in graph.edges:
        if u not in positions or v not in positions:
            continue
        x1, y1 = positions[u]
        x2, y2 = positions[v]
        is_cut = (u, v) in cut_edges
        active = u in highlight_nodes and v in highlight_nodes

        if is_cut:
            stroke, width_px, opacity = "#ff5c6c", 4, "1"
        elif active:
            stroke, width_px, opacity = "#43c6ff", 2.8, "1"
        else:
            stroke, width_px, opacity = "#29435f", 1.5, "0.15" if fade_outside else "0.55"

        edge_parts.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
            f'stroke="{stroke}" stroke-width="{width_px}" opacity="{opacity}" '
            f'stroke-linecap="round"/>'
        )

    node_parts = []
    for node in graph.nodes:
        if node not in positions:
            continue
        x, y = positions[node]

        if node == attacker:
            fill, stroke = "#4d1219", "#ff5c6c"
        elif node == target:
            fill, stroke = "#173d2e", "#51d88a"
        else:
            fill, stroke = "#122131", "#5f7891"

        opacity = "1" if node in highlight_nodes or node in {attacker, target} else "0.25"
        node_parts.append(
            f'<g opacity="{opacity}"><circle cx="{x}" cy="{y}" r="12" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
            f'<text x="{x}" y="{y+28}" fill="#dfe9f2" font-size="10" '
            f'text-anchor="middle">{html.escape(str(node))}</text></g>'
        )

    return (
        '<div style="border:1px solid #27415c;border-radius:16px;padding:8px;'
        'background:radial-gradient(circle at 50% 45%,#102438 0,#091522 60%,#07111f 100%);">'
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'preserveAspectRatio="xMidYMid meet">{"".join(edge_parts)}{"".join(node_parts)}</svg>'
        "</div>"
    )


def _verify(graph: nx.DiGraph, attacker: str, targets: Iterable[str]) -> dict[str, bool]:
    return {
        target: (
            nx.has_path(graph, attacker, target)
            if attacker in graph and target in graph
            else False
        )
        for target in targets
    }


st.title("ShadowCut Security Console")
st.caption("LANL enterprise authentication evidence mode — same containment controller, real telemetry source")

with st.sidebar:
    st.header("LANL Input")
    auth_path = st.text_input(
        "LANL authentication file",
        value="data/lanl/auth.txt.gz",
        help="Official LANL Comprehensive Multi-Source auth.txt.gz",
    )
    redteam_path = st.text_input(
        "LANL red-team file",
        value="data/lanl/redteam.txt.gz",
        help="Official LANL redteam.txt.gz",
    )
    incident_index = st.number_input("Red-team incident index", min_value=0, value=0, step=1)
    window_before_hours = st.number_input("Window before incident (hours)", min_value=0.25, value=6.0, step=0.25)
    window_after_hours = st.number_input("Window after incident (hours)", min_value=0.25, value=1.0, step=0.25)
    max_events = st.number_input("Maximum auth events to ingest", min_value=1_000, max_value=1_000_000, value=100_000, step=10_000)

    st.divider()
    budget = st.number_input("Disruption budget", min_value=1.0, value=10.0, step=1.0)
    initial_k = st.number_input("Initial radius k", min_value=1, value=2, step=1)
    max_k = st.number_input("Maximum radius k", min_value=initial_k, value=max(4, initial_k), step=1)
    display_radius = st.number_input("Visualization radius", min_value=1, value=3, step=1)

    load = st.button("Load LANL Snapshot", type="primary", use_container_width=True)
    run = st.button("Run ShadowCut", use_container_width=True)

if "snapshot" not in st.session_state:
    st.session_state.snapshot = None
if "result" not in st.session_state:
    st.session_state.result = None

if load:
    try:
        snapshot = build_lanl_snapshot(
            auth_path,
            redteam_path,
            incident_index=int(incident_index),
            window_before=float(window_before_hours) * 3600.0,
            window_after=float(window_after_hours) * 3600.0,
            max_events=int(max_events),
        )
        st.session_state.snapshot = snapshot
        st.session_state.result = None
        st.success("LANL snapshot loaded.")
    except Exception as exc:
        st.error(f"LANL load failed: {exc}")

snapshot = st.session_state.snapshot

if snapshot is None:
    st.info(
        "Place the official LANL auth.txt.gz and redteam.txt.gz files at the configured paths, "
        "then click Load LANL Snapshot."
    )
    st.stop()

incident = snapshot.incident
display_graph = _display_graph(snapshot, radius=int(display_radius))

c1, c2, c3, c4 = st.columns(4)
c1.metric("Auth events used", f"{snapshot.stats.events_used:,}")
c2.metric("Graph nodes", f"{snapshot.stats.nodes:,}")
c3.metric("Graph edges", f"{snapshot.stats.edges:,}")
c4.metric("Red-team time", f"{incident.event.timestamp:.0f}")

st.markdown(
    f"""
    <div class="panel">
      <strong>Ground-truth incident</strong><br/>
      <span class="muted">LANL red-team event</span><br/><br/>
      Attacker: <code>{html.escape(incident.attacker)}</code><br/>
      Destination: <code>{html.escape(incident.target)}</code><br/>
      User: <code>{html.escape(incident.event.user)}</code><br/>
      Time: <code>{incident.event.timestamp}</code>
    </div>
    """,
    unsafe_allow_html=True,
)

st.subheader("Incident neighborhood")
st.markdown(
    _build_svg(
        display_graph,
        highlight_nodes={incident.attacker, incident.target},
        attacker=incident.attacker,
        target=incident.target,
    ),
    unsafe_allow_html=True,
)
st.caption(
    "Visualization shows only the incident-centered display neighborhood; ShadowCut is run "
    "against the full ingested graph snapshot."
)

if run:
    controller = ShadowCutController(snapshot.graph.G)
    with st.spinner("Running ShadowCut on the LANL-derived graph..."):
        result = controller.analyze_incident(
            attacker=incident.attacker,
            targets=[incident.target],
            budget=float(budget),
            initial_radius=int(initial_k),
            max_radius=int(max_k),
        )
    st.session_state.result = result

result = st.session_state.result
if result is None:
    st.info("Click Run ShadowCut to execute the containment analysis.")
    st.stop()

display_graph = _display_graph(snapshot, radius=max(int(display_radius), int(result.final_radius)))

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Final k", str(result.final_radius))
m2.metric("Locality", f"{result.locality_vertex_ratio * 100:.1f}% nodes")
m3.metric("Max flow", "N/A" if result.max_flow is None else f"{result.max_flow:.1f}")
m4.metric("Cut cost", f"{result.disruption_cost:.1f} / {float(budget):.1f}")
m5.metric("Containment", "PASSED" if result.global_containment else "FAILED")

contained_graph = snapshot.graph.G.copy()
contained_graph.remove_edges_from(result.selected_edges)
reachability = _verify(contained_graph, incident.attacker, [incident.target])
contained = not any(reachability.values())

st.markdown("### Proposed containment")
if result.selected_edges:
    chips = "".join(
        f'<span class="chip">{html.escape(u)} -&gt; {html.escape(v)}</span>'
        for u, v in sorted(result.selected_edges)
    )
    st.markdown(chips, unsafe_allow_html=True)
else:
    st.caption("No containment edges were selected within the configured budget.")

st.markdown("### Post-containment graph")
cut_edges = set(result.selected_edges)
post_display = _display_graph(snapshot, radius=max(int(display_radius), int(result.final_radius)))
st.markdown(
    _build_svg(
        post_display,
        highlight_nodes={incident.attacker, incident.target},
        attacker=incident.attacker,
        target=incident.target,
        cut_edges=cut_edges,
    ),
    unsafe_allow_html=True,
)

st.markdown("### Independent global verification")
status = "PASSED" if contained else "FAILED"
css = "success" if contained else "fail"
st.markdown(
    f'<div class="panel"><strong class="{css}">GLOBAL CONTAINMENT {status}</strong><br/>'
    f'<span class="muted">{html.escape(result.validation_message)}</span></div>',
    unsafe_allow_html=True,
)
st.json(
    {
        "attacker": incident.attacker,
        "target": incident.target,
        "target_reachable_after_cut": reachability[incident.target],
        "global_containment": contained,
        "selected_edges": sorted(result.selected_edges),
        "disruption_cost": result.disruption_cost,
        "final_radius": result.final_radius,
    }
)
