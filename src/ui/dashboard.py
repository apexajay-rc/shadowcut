import html
import time
from typing import Dict, Iterable, Optional, Set, Tuple

import networkx as nx
import streamlit as st

from demo_scenario import ATTACKER, ATTACK_PATH, PROTECTED_ASSETS, build_demo_graph
from shadowcut_controller import ShadowCutController


st.set_page_config(
    page_title="ShadowCut Security Console",
    page_icon="SC",
    layout="wide",
    initial_sidebar_state="collapsed",
)


CSS = """
<style>
:root {
    --bg: #07111f;
    --panel: #0d1b2a;
    --panel2: #10253a;
    --text: #e6edf5;
    --muted: #91a4b7;
    --line: #27415c;
    --cyan: #43c6ff;
    --red: #ff5c6c;
    --green: #51d88a;
    --amber: #f3bf52;
}

.stApp {
    background: var(--bg);
    color: var(--text);
}

.block-container {
    padding-top: 1.2rem;
    max-width: 1500px;
}

.sc-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 18px;
    border: 1px solid var(--line);
    border-radius: 16px;
    background: linear-gradient(135deg, #0d1b2a, #0b1724);
    margin-bottom: 14px;
}

.sc-title {
    font-size: 24px;
    font-weight: 700;
    letter-spacing: .02em;
}

.sc-sub {
    color: var(--muted);
    font-size: 13px;
    margin-top: 4px;
}

.status {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--green);
    font-weight: 600;
    font-size: 13px;
}

.dot {
    width: 9px;
    height: 9px;
    background: var(--green);
    border-radius: 50%;
    box-shadow: 0 0 12px rgba(81, 216, 138, .6);
}

.network {
    border: 1px solid var(--line);
    border-radius: 16px;
    background: radial-gradient(
        circle at 50% 45%,
        #102438 0,
        #091522 60%,
        #07111f 100%
    );
    padding: 12px;
}

.phase {
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 14px;
    background: var(--panel);
    margin-bottom: 10px;
}

.phase-title {
    font-size: 12px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: .12em;
}

.phase-value {
    margin-top: 5px;
    font-size: 20px;
    font-weight: 700;
}

.metric {
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 12px;
    background: var(--panel);
}

.metric-label {
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .08em;
}

.metric-value {
    font-size: 22px;
    font-weight: 700;
    margin-top: 4px;
}

.success {
    color: var(--green);
}

.warn {
    color: var(--amber);
}

.fail {
    color: var(--red);
}

.cut-chip {
    display: inline-block;
    padding: 6px 8px;
    border: 1px solid #7f3641;
    border-radius: 8px;
    margin: 3px;
    background: #24131a;
    color: #ff9aa5;
    font-family: monospace;
    font-size: 11px;
}

.small {
    font-size: 12px;
    color: var(--muted);
}

.phase-step {
    display: inline-block;
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 6px 9px;
    margin: 2px;
    font-size: 11px;
    color: var(--muted);
    background: #091522;
}

.phase-step-active {
    color: var(--cyan);
    border-color: var(--cyan);
}

.phase-step-done {
    color: var(--green);
    border-color: #2e6e50;
}

.verify-box {
    border: 1px solid #2e6e50;
    border-radius: 14px;
    padding: 18px;
    background: rgba(30, 89, 58, .18);
    text-align: center;
}

.verify-title {
    color: var(--green);
    font-size: 24px;
    font-weight: 800;
    letter-spacing: .04em;
}

.verify-sub {
    color: #b7e7cb;
    margin-top: 6px;
    font-size: 13px;
}

.edge-list {
    font-family: monospace;
    font-size: 12px;
    line-height: 1.8;
}
</style>
"""

st.markdown(CSS, unsafe_allow_html=True)


PHASES = [
    "ATTACK",
    "DETECT",
    "LOCALIZE",
    "OPTIMIZE",
    "SELECT",
    "APPLY",
    "VERIFY",
    "COMPLETE",
]


def init_state() -> None:
    defaults = {
        "run_complete": False,
        "result": None,
        "blocked_edges": set(),
        "final_graph": None,
        "verified_targets": [],
        "attack_path_reached": False,
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def phase_bar(active: Optional[str] = None, completed: Optional[Iterable[str]] = None) -> str:
    completed = set(completed or [])

    pieces = []

    for phase in PHASES:
        if phase in completed:
            cls = "phase-step phase-step-done"
            symbol = "✓"
        elif phase == active:
            cls = "phase-step phase-step-active"
            symbol = "●"
        else:
            cls = "phase-step"
            symbol = "○"

        pieces.append(
            f'<span class="{cls}">{symbol} {phase}</span>'
        )

    return " ".join(pieces)


def node_position(node: str, graph: nx.DiGraph) -> Tuple[float, float]:
    pos = graph.graph.get("ui_pos", {})
    return pos.get(node, (50.0, 50.0))


def build_svg(
    graph: nx.DiGraph,
    highlight_nodes: Optional[Set[str]] = None,
    attacker: Optional[str] = None,
    fade_outside: bool = False,
    attack_edges: Optional[Set[Tuple[str, str]]] = None,
    height: int = 560,
) -> str:
    highlight_nodes = set(highlight_nodes or [])
    attack_edges = set(attack_edges or [])
    attacker = attacker or ""

    positions = graph.graph["ui_pos"]

    width = 1100
    edge_svg = []
    node_svg = []

    for u, v, _data in graph.edges(data=True):
        x1, y1 = positions[u]
        x2, y2 = positions[v]

        active = u in highlight_nodes and v in highlight_nodes
        is_attack = (u, v) in attack_edges

        if is_attack:
            stroke = "#ff5c6c"
            stroke_width = 4
            opacity = "1"
        elif active:
            stroke = "#43c6ff"
            stroke_width = 2.6
            opacity = "1"
        else:
            stroke = "#29435f"
            stroke_width = 1.4
            opacity = "0.16" if fade_outside else "0.50"

        edge_svg.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
            f'stroke="{stroke}" stroke-width="{stroke_width}" '
            f'opacity="{opacity}" stroke-linecap="round"/>'
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

        if active or node == attacker or kind == "critical":
            opacity = "1"
        else:
            opacity = "0.22" if fade_outside else "0.85"

        radius = 16 if kind != "pc" else 12
        label = html.escape(node)

        node_svg.append(
            f'<g opacity="{opacity}">'
            f'<circle cx="{x}" cy="{y}" r="{radius}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
            f'<text x="{x}" y="{y + 29}" fill="#dfe9f2" '
            f'font-size="10" text-anchor="middle">{label}</text>'
            f'</g>'
        )

    return f"""
    <div class="network">
        <svg viewBox="0 0 {width} {height}"
             width="100%"
             height="{height}"
             preserveAspectRatio="xMidYMid meet">
            <defs>
                <filter id="glow">
                    <feGaussianBlur stdDeviation="4" result="blur"/>
                    <feMerge>
                        <feMergeNode in="blur"/>
                        <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                </filter>
            </defs>
            {''.join(edge_svg)}
            {''.join(node_svg)}
        </svg>
    </div>
    """


def position_demo_graph(graph: nx.DiGraph) -> None:
    positions: Dict[str, Tuple[float, float]] = {}

    pcs = [n for n in graph.nodes if n.startswith("PC-")]

    for idx, node in enumerate(pcs):
        row, col = divmod(idx, 7)
        positions[node] = (
            75 + col * 92,
            70 + row * 72,
        )

    positions.update(
        {
            "WEB-01": (340, 110),
            "APP-01": (500, 180),
            "DB-01": (660, 260),
            "ID-01": (620, 120),
            "FILE-01": (790, 120),
            "FIN-01": (800, 280),
            "VAULT": (980, 235),
        }
    )

    graph.graph["ui_pos"] = positions


def verify_full_graph(
    graph: nx.DiGraph,
    attacker: str,
    targets: Iterable[str],
) -> Tuple[bool, Dict[str, bool]]:
    reachability: Dict[str, bool] = {}

    for target in targets:
        if attacker not in graph or target not in graph:
            reachability[target] = False
            continue

        reachability[target] = nx.has_path(graph, attacker, target)

    contained = not any(reachability.values())
    return contained, reachability


def render_phase(
    phase_box,
    network_placeholder,
    graph: nx.DiGraph,
    message: str,
    *,
    highlight_nodes: Optional[Set[str]] = None,
    fade_outside: bool = False,
    attack_edges: Optional[Set[Tuple[str, str]]] = None,
    attacker: str = ATTACKER,
) -> None:
    phase_box.info(message)

    network_placeholder.markdown(
        build_svg(
            graph,
            highlight_nodes=highlight_nodes,
            attacker=attacker,
            fade_outside=fade_outside,
            attack_edges=attack_edges,
        ),
        unsafe_allow_html=True,
    )


init_state()

graph = build_demo_graph()
position_demo_graph(graph)

controller = ShadowCutController(graph)

st.markdown(
    """
    <div class="sc-header">
        <div>
            <div class="sc-title">ShadowCut Security Console</div>
            <div class="sc-sub">
                Locality-aware lateral movement containment and verification
            </div>
        </div>
        <div class="status">
            <span class="dot"></span>
            SYSTEM ONLINE
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


left, right = st.columns([3.2, 1.2])


with right:
    st.markdown(
        """
        <div class="phase">
            <div class="phase-title">Network State</div>
            <div class="phase-value">28 PCs + 7 servers</div>
            <div class="small">35 nodes / controlled enterprise topology</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <div class="phase">
            <div class="phase-title">Protected Assets</div>
            <div class="phase-value">{len(PROTECTED_ASSETS)}</div>
            <div class="small">
                {", ".join(PROTECTED_ASSETS)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    budget = st.slider(
        "Disruption budget",
        min_value=1.0,
        max_value=20.0,
        value=10.0,
        step=1.0,
    )

    initial_k = st.slider(
        "Initial radius",
        min_value=1,
        max_value=4,
        value=2,
    )

    max_k = st.slider(
        "Maximum radius",
        min_value=initial_k,
        max_value=6,
        value=max(4, initial_k),
    )

    run = st.button(
        "Simulate Attack & Run ShadowCut",
        type="primary",
        use_container_width=True,
    )

    reset = st.button(
        "Reset Demo",
        use_container_width=True,
    )


with left:
    st.subheader("Enterprise Network")

    network_placeholder = st.empty()

    # Always show the appropriate current graph before a run.
    if st.session_state.run_complete and st.session_state.final_graph is not None:
        display_graph = st.session_state.final_graph
        network_placeholder.markdown(
            build_svg(
                display_graph,
                highlight_nodes=set(PROTECTED_ASSETS),
                attacker=ATTACKER,
                fade_outside=False,
            ),
            unsafe_allow_html=True,
        )
    else:
        network_placeholder.markdown(
            build_svg(graph),
            unsafe_allow_html=True,
        )

    st.markdown(phase_bar(completed=["COMPLETE"] if st.session_state.run_complete else []),
                unsafe_allow_html=True)


if reset:
    st.session_state.run_complete = False
    st.session_state.result = None
    st.session_state.blocked_edges = set()
    st.session_state.final_graph = None
    st.session_state.verified_targets = []
    st.session_state.attack_path_reached = False
    st.rerun()


if run:
    st.session_state.run_complete = False
    st.session_state.result = None
    st.session_state.blocked_edges = set()
    st.session_state.final_graph = None
    st.session_state.verified_targets = []
    st.session_state.attack_path_reached = False

    phase_box = st.empty()

    # ------------------------------------------------------------------
    # PHASE 1: ATTACK
    # ------------------------------------------------------------------
    completed = set()

    phase_box.markdown(phase_bar("ATTACK", completed), unsafe_allow_html=True)

    visited = set()
    for index in range(len(ATTACK_PATH)):
        visited.add(ATTACK_PATH[index])

        current_edges = set(
            zip(
                ATTACK_PATH[:index],
                ATTACK_PATH[1 : index + 1],
            )
        )

        render_phase(
            phase_box,
            network_placeholder,
            graph,
            f"Simulating lateral movement: {ATTACK_PATH[index]}",
            highlight_nodes=set(visited),
            attack_edges=current_edges,
            attacker=ATTACKER,
        )

        time.sleep(0.45)

    st.session_state.attack_path_reached = True

    # ------------------------------------------------------------------
    # PHASE 2: DETECT
    # ------------------------------------------------------------------
    completed.add("ATTACK")

    phase_box.markdown(
        phase_bar("DETECT", completed),
        unsafe_allow_html=True,
    )

    render_phase(
        phase_box,
        network_placeholder,
        graph,
        f"Incident detected: {ATTACKER} is exhibiting suspicious lateral movement toward protected assets.",
        highlight_nodes=set(ATTACK_PATH),
        attack_edges=set(zip(ATTACK_PATH[:-1], ATTACK_PATH[1:])),
        attacker=ATTACKER,
    )

    time.sleep(0.9)

    # ------------------------------------------------------------------
    # PHASE 3: LOCALIZE
    # ------------------------------------------------------------------
    completed.add("DETECT")

    local_nodes = set(
        nx.ego_graph(
            graph,
            ATTACKER,
            radius=initial_k,
            undirected=False,
        ).nodes
    )

    phase_box.markdown(
        phase_bar("LOCALIZE", completed),
        unsafe_allow_html=True,
    )

    render_phase(
        phase_box,
        network_placeholder,
        graph,
        f"Extracting incident-centered neighborhood: k={initial_k}",
        highlight_nodes=local_nodes,
        fade_outside=True,
        attacker=ATTACKER,
    )

    time.sleep(1.0)

    # ------------------------------------------------------------------
    # PHASE 4: OPTIMIZE
    # ------------------------------------------------------------------
    completed.add("LOCALIZE")

    phase_box.markdown(
        phase_bar("OPTIMIZE", completed),
        unsafe_allow_html=True,
    )

    phase_box.info(
        "Running maximum-flow / minimum-cut optimization on the localized graph..."
    )

    result = controller.analyze_incident(
        attacker=ATTACKER,
        targets=PROTECTED_ASSETS,
        budget=budget,
        initial_radius=initial_k,
        max_radius=max_k,
        attack_path=ATTACK_PATH,
    )

    final_local_nodes = set(
        nx.ego_graph(
            graph,
            ATTACKER,
            radius=result.final_radius,
            undirected=False,
        ).nodes
    )

    network_placeholder.markdown(
        build_svg(
            graph,
            highlight_nodes=final_local_nodes,
            attacker=ATTACKER,
            fade_outside=True,
        ),
        unsafe_allow_html=True,
    )

    time.sleep(1.0)

    # ------------------------------------------------------------------
    # PHASE 5: SELECT
    # ------------------------------------------------------------------
    completed.add("OPTIMIZE")

    phase_box.markdown(
        phase_bar("SELECT", completed),
        unsafe_allow_html=True,
    )

    phase_box.info("Applying the greedy multi-asset containment decision...")

    time.sleep(0.8)

    if result.expanded:
        phase_box.warning(
            f"Local solution required expansion: "
            f"k={result.initial_radius} → k={result.final_radius}. "
            f"Global validation is being checked on the full graph."
        )
        time.sleep(0.9)

    # ------------------------------------------------------------------
    # PHASE 6: APPLY
    # ------------------------------------------------------------------
    completed.add("SELECT")

    phase_box.markdown(
        phase_bar("APPLY", completed),
        unsafe_allow_html=True,
    )

    phase_box.info("Applying selected containment edges to the simulated network state...")

    contained_graph = graph.copy()
    blocked_edges = set(result.selected_edges)

    contained_graph.remove_edges_from(blocked_edges)

    st.session_state.blocked_edges = blocked_edges
    st.session_state.final_graph = contained_graph

    # Show the actual post-containment topology.
    network_placeholder.markdown(
        build_svg(
            contained_graph,
            highlight_nodes=set(PROTECTED_ASSETS),
            attacker=ATTACKER,
            fade_outside=False,
        ),
        unsafe_allow_html=True,
    )

    time.sleep(1.2)

    # ------------------------------------------------------------------
    # PHASE 7: VERIFY
    # ------------------------------------------------------------------
    completed.add("APPLY")

    phase_box.markdown(
        phase_bar("VERIFY", completed),
        unsafe_allow_html=True,
    )

    phase_box.info("Performing independent full-graph reachability verification...")

    verified, reachability = verify_full_graph(
        contained_graph,
        ATTACKER,
        PROTECTED_ASSETS,
    )

    st.session_state.verified_targets = reachability

    time.sleep(1.0)

    # ------------------------------------------------------------------
    # PHASE 8: COMPLETE
    # ------------------------------------------------------------------
    completed.add("VERIFY")

    if verified:
        completed.add("COMPLETE")

        phase_box.markdown(
            phase_bar("COMPLETE", completed),
            unsafe_allow_html=True,
        )

        phase_box.success(
            "CONTAINMENT VERIFIED — no attacker-to-protected-asset path remains in the simulated network."
        )
    else:
        phase_box.error(
            "CONTAINMENT FAILED — at least one protected asset remains reachable."
        )

    st.session_state.result = result
    st.session_state.run_complete = True


# ======================================================================
# FINAL RESULT PANEL
# ======================================================================

if st.session_state.run_complete and st.session_state.result is not None:
    result = st.session_state.result

    st.markdown("### Decision")

    metric_cols = st.columns(5)

    metrics = [
        ("Final k", str(result.final_radius)),
        ("Locality", f"{result.locality_vertex_ratio * 100:.1f}% nodes"),
        (
            "Max flow",
            f"{result.max_flow:.1f}" if result.max_flow is not None else "N/A",
        ),
        ("Cut cost", f"{result.disruption_cost:.1f} / {budget:.1f}"),
        (
            "Validation",
            "PASSED" if result.global_containment else "FAILED",
        ),
    ]

    for col, (label, value) in zip(metric_cols, metrics):
        value_class = ""
        if label == "Validation":
            value_class = "success" if result.global_containment else "fail"

        col.markdown(
            f"""
            <div class="metric">
                <div class="metric-label">{label}</div>
                <div class="metric-value {value_class}">{value}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("### Greedy containment selection")

    if result.candidate_history:
        history = result.candidate_history[-1].get("greedy", [])

        if history:
            for item in history:
                st.markdown(
                    f"""
                    **{html.escape(item["target"])}**
                    — incremental cost
                    `{item["incremental_cost"]:.1f}`
                    — cumulative cost
                    `{item["total_cost"]:.1f}`
                    — **SELECTED**
                    """
                )
        else:
            st.markdown(
                '<span class="small">No candidate could be selected within the configured budget.</span>',
                unsafe_allow_html=True,
            )

    st.markdown("### Connections severed")

    if st.session_state.blocked_edges:
        chips = "".join(
            f'<span class="cut-chip">'
            f'{html.escape(u)} -&gt; {html.escape(v)}'
            f'</span>'
            for u, v in sorted(st.session_state.blocked_edges)
        )

        st.markdown(chips, unsafe_allow_html=True)
    else:
        st.markdown(
            '<span class="small">No connections were severed.</span>',
            unsafe_allow_html=True,
        )

    st.markdown("### Global reachability verification")

    verification_rows = []

    for target, reachable in st.session_state.verified_targets.items():
        verification_rows.append(
            (
                target,
                "PATH EXISTS" if reachable else "NO PATH",
                reachable,
            )
        )

    for target, status, reachable in verification_rows:
        css_class = "fail" if reachable else "success"

        st.markdown(
            f"""
            <div class="edge-list">
                <span>{ATTACKER}</span>
                →
                <span>{html.escape(target)}</span>
                :
                <strong class="{css_class}">{status}</strong>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if result.global_containment:
        st.markdown(
            """
            <div class="verify-box">
                <div class="verify-title">CONTAINMENT VERIFIED</div>
                <div class="verify-sub">
                    The post-containment graph contains no reachable path
                    from the compromised host to any protected asset.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.error(result.validation_message)
