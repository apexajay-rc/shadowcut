from demo_scenario import ATTACK_PATH, ATTACKER, PROTECTED_ASSETS
from demo_scenario import build_demo_graph
from shadowcut_controller import ShadowCutController


def run_pipeline() -> None:
    graph = build_demo_graph()
    controller = ShadowCutController(graph)
    result = controller.analyze_incident(
        attacker=ATTACKER,
        targets=PROTECTED_ASSETS,
        budget=10.0,
        initial_radius=2,
        max_radius=5,
        attack_path=ATTACK_PATH,
    )

    print("=== ShadowCut Incident Analysis ===")
    print(f"Incident detected : {result.incident_detected}")
    print(f"Initial radius    : k={result.initial_radius}")
    print(f"Final radius      : k={result.final_radius}")
    print(f"Locality          : {result.locality_vertex_ratio:.2%} of nodes / {result.locality_edge_ratio:.2%} of edges")
    print(f"Max flow          : {result.max_flow}")
    print(f"Primary min-cut   : {result.min_cut_cost}")
    print(f"Selected edges    : {result.selected_edges}")
    print(f"Disruption cost   : {result.disruption_cost:.2f} / 10.00")
    print(f"Protected assets  : {result.protected_assets}")
    print(f"Unprotected       : {result.unprotected_assets}")
    print(f"Global containment: {result.global_containment}")
    print(f"Validation        : {result.validation_message}")


if __name__ == "__main__":
    run_pipeline()
