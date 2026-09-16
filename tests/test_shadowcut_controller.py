import sys
from pathlib import Path

import networkx as nx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from demo_scenario import ATTACKER, PROTECTED_ASSETS, build_demo_graph
from shadowcut_controller import ShadowCutController


def test_local_bypass_is_detected_and_radius_expands():
    g = nx.DiGraph()
    g.add_edge('S', 'A', cost=1)
    g.add_edge('A', 'T', cost=1)
    g.add_edge('S', 'B', cost=0.5)
    g.add_edge('B', 'C', cost=0.5)
    g.add_edge('C', 'D', cost=100)
    g.add_edge('D', 'T', cost=100)

    result = ShadowCutController(g).analyze_incident('S', ['T'], budget=5, initial_radius=2, max_radius=4)
    assert result.expanded is True
    assert result.global_containment is True
    assert result.final_radius >= 3


def test_demo_scenario_reaches_verified_containment():
    g = build_demo_graph()
    result = ShadowCutController(g).analyze_incident(
        ATTACKER, PROTECTED_ASSETS, budget=10, initial_radius=2, max_radius=5
    )
    assert result.incident_detected is True
    assert result.global_containment is True
    assert not result.unprotected_assets
    assert result.disruption_cost <= 10


def test_budget_can_leave_assets_unprotected():
    g = nx.DiGraph()
    g.add_edge('S', 'A', cost=2)
    g.add_edge('A', 'T1', cost=3)
    g.add_edge('S', 'B', cost=2)
    g.add_edge('B', 'T2', cost=3)

    result = ShadowCutController(g).analyze_incident('S', ['T1', 'T2'], budget=3, initial_radius=2, max_radius=2)
    assert result.global_containment is False
    assert result.unprotected_assets
