"""
CLI for the LANL evidence-mode demo.

Usage:
    PYTHONPATH=./src python3 src/main_lanl.py \
        --auth data/lanl/auth.txt.gz \
        --redteam data/lanl/redteam.txt.gz
"""

from __future__ import annotations

import argparse

from ingestion.lanl_snapshot import build_lanl_snapshot
from shadowcut_controller import ShadowCutController


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run ShadowCut on a LANL snapshot.")
    parser.add_argument("--auth", required=True, help="Path to LANL auth.txt or auth.txt.gz")
    parser.add_argument("--redteam", required=True, help="Path to LANL redteam.txt or redteam.txt.gz")
    parser.add_argument("--incident-index", type=int, default=0)
    parser.add_argument("--window-before", type=float, default=6 * 60 * 60)
    parser.add_argument("--window-after", type=float, default=60 * 60)
    parser.add_argument("--max-events", type=int, default=100_000)
    parser.add_argument("--budget", type=float, default=10.0)
    parser.add_argument("--initial-k", type=int, default=2)
    parser.add_argument("--max-k", type=int, default=5)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    snapshot = build_lanl_snapshot(
        args.auth,
        args.redteam,
        incident_index=args.incident_index,
        window_before=args.window_before,
        window_after=args.window_after,
        max_events=args.max_events,
    )

    graph = snapshot.graph.G
    incident = snapshot.incident

    print("=== ShadowCut LANL Evidence Mode ===")
    print(f"Incident index    : {args.incident_index}")
    print(f"Red-team time     : {incident.event.timestamp}")
    print(f"Attacker          : {incident.attacker}")
    print(f"Target            : {incident.target}")
    print(f"Events used       : {snapshot.stats.events_used:,}")
    print(f"Graph nodes       : {snapshot.stats.nodes:,}")
    print(f"Graph edges       : {snapshot.stats.edges:,}")

    controller = ShadowCutController(graph)
    result = controller.analyze_incident(
        attacker=incident.attacker,
        targets=[incident.target],
        budget=args.budget,
        initial_radius=args.initial_k,
        max_radius=args.max_k,
    )

    print("--- ShadowCut ---")
    print(f"Incident detected : {result.incident_detected}")
    print(f"Final radius      : k={result.final_radius}")
    print(f"Locality          : {result.locality_vertex_ratio:.2%} nodes / "
          f"{result.locality_edge_ratio:.2%} edges")
    print(f"Max flow          : {result.max_flow}")
    print(f"Primary min-cut   : {result.min_cut_cost}")
    print(f"Selected edges    : {result.selected_edges}")
    print(f"Disruption cost   : {result.disruption_cost:.2f} / {args.budget:.2f}")
    print(f"Global containment: {result.global_containment}")
    print(f"Validation        : {result.validation_message}")


if __name__ == "__main__":
    main()
