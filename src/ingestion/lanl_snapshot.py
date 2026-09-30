"""
High-level LANL snapshot builder.

This module is the bridge between the raw LANL files and the existing
ShadowCutController. It deliberately does not change the containment engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from graph.graph_state import EnterpriseGraph
from ingestion.lanl_parser import (
    LANLRedTeamEvent,
    LANLSnapshotStats,
    build_auth_graph,
    load_redteam_events,
)


@dataclass(frozen=True, slots=True)
class LANLIncident:
    """A LANL red-team event interpreted as a containment scenario."""

    event: LANLRedTeamEvent
    attacker: str
    target: str


@dataclass(frozen=True, slots=True)
class LANLSnapshot:
    graph: EnterpriseGraph
    incident: LANLIncident
    stats: LANLSnapshotStats


def build_lanl_snapshot(
    auth_path: str | Path,
    redteam_path: str | Path,
    *,
    incident_index: int = 0,
    window_before: float = 6 * 60 * 60,
    window_after: float = 60 * 60,
    max_events: int = 100_000,
    disruption_cost: float = 1.0,
) -> LANLSnapshot:
    """
    Build a manageable, incident-centered graph snapshot.

    We use:
        attacker = red-team source computer
        target   = red-team destination computer

    This is an explicit demo/evaluation interpretation. The LANL red-team
    file is ground truth for compromise events; it does not label business
    criticality, so the destination is treated as the protected target for
    this scenario rather than as a universally "critical asset".
    """
    incidents = load_redteam_events(redteam_path)
    if not incidents:
        raise ValueError("No LANL red-team events were found.")

    if not 0 <= incident_index < len(incidents):
        raise IndexError(
            f"incident_index={incident_index} is out of range; "
            f"LANL red-team file contains {len(incidents)} events."
        )

    event = incidents[incident_index]
    start_time = max(1.0, event.timestamp - window_before)
    end_time = event.timestamp + window_after

    graph = EnterpriseGraph()
    stats = build_auth_graph(
        auth_path,
        graph,
        success_only=True,
        start_time=start_time,
        end_time=end_time,
        max_events=max_events,
        disruption_cost=disruption_cost,
    )

    # The red-team source/destination may not have a successful-auth edge in
    # the selected window, but they should still be available as nodes so the
    # dashboard can identify the incident.
    graph.G.add_node(event.source_computer, kind="pc", source="lanl_redteam")
    graph.G.add_node(event.destination_computer, kind="pc", source="lanl_redteam")

    # Refresh counts after adding red-team incident nodes that were absent from
    # the selected authentication window.
    stats = LANLSnapshotStats(
        events_read=stats.events_read,
        events_used=stats.events_used,
        events_skipped=stats.events_skipped,
        nodes=graph.G.number_of_nodes(),
        edges=graph.G.number_of_edges(),
        start_time=stats.start_time,
        end_time=stats.end_time,
    )

    incident = LANLIncident(
        event=event,
        attacker=event.source_computer,
        target=event.destination_computer,
    )

    return LANLSnapshot(
        graph=graph,
        incident=incident,
        stats=stats,
    )
