from pathlib import Path

import networkx as nx

from ingestion.lanl_parser import (
    build_auth_graph,
    load_redteam_events,
    parse_auth_line,
    parse_redteam_line,
)
from ingestion.lanl_snapshot import build_lanl_snapshot
from graph.graph_state import EnterpriseGraph


FIXTURES = Path(__file__).parent / "fixtures" / "lanl"


def test_parse_official_auth_shape():
    event = parse_auth_line(
        "1,C625$@DOM1,U147@DOM1,C625,C625,Negotiate,Batch,LogOn,Success"
    )
    assert event.timestamp == 1
    assert event.source_computer == "C625"
    assert event.destination_computer == "C625"
    assert event.status == "Success"


def test_parse_official_redteam_shape():
    event = parse_redteam_line("151648,U748@DOM1,C17693,C728")
    assert event.timestamp == 151648
    assert event.source_computer == "C17693"
    assert event.destination_computer == "C728"


def test_build_auth_graph_streams_and_filters_failures():
    graph = EnterpriseGraph()
    stats = build_auth_graph(
        FIXTURES / "auth_sample.txt",
        graph,
        start_time=100,
        end_time=140,
        max_events=100,
    )

    assert stats.events_used == 8
    assert stats.nodes == 8
    assert stats.edges == 8
    assert graph.G.has_edge("C001", "C002")
    assert graph.G["C001"]["C002"]["observations"] == 1
    assert graph.G["C001"]["C002"]["cost"] == 1.0


def test_build_lanl_snapshot_selects_incident():
    snapshot = build_lanl_snapshot(
        FIXTURES / "auth_sample.txt",
        FIXTURES / "redteam_sample.txt",
        window_before=100,
        window_after=20,
        max_events=100,
    )

    assert snapshot.incident.attacker == "C001"
    assert snapshot.incident.target == "C020"
    assert snapshot.incident.event.user == "U999@DOM1"
    assert snapshot.graph.G.has_node("C001")
    assert snapshot.graph.G.has_node("C020")
