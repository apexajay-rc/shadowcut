from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple
import time
import networkx as nx

Edge = Tuple[str, str]

@dataclass
class CutCandidate:
    target: str
    flow_value: float
    cut_edges: Set[Edge]
    cut_cost: float
    reachable_nodes: Set[str] = field(default_factory=set)
    protected_nodes: Set[str] = field(default_factory=set)

@dataclass
class IncidentResult:
    incident_detected: bool
    attacker: str
    targets: List[str]
    initial_radius: int
    final_radius: int
    max_radius: int
    expanded: bool
    local_nodes: int
    local_edges: int
    global_nodes: int
    global_edges: int
    locality_vertex_ratio: float
    locality_edge_ratio: float
    max_flow: Optional[float]
    min_cut_cost: Optional[float]
    cut_edges: List[Edge]
    selected_edges: List[Edge]
    disruption_cost: float
    protected_assets: List[str]
    unprotected_assets: List[str]
    global_containment: bool
    validation_message: str
    phase_timings_ms: Dict[str, float]
    attack_path: List[str]
    candidate_history: List[Dict]

class ShadowCutController:
    """Single orchestration entry point for the ShadowCut demo and backend."""

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    @staticmethod
    def _cut_edges(subgraph: nx.DiGraph, reachable: Set[str], protected: Set[str]) -> Set[Edge]:
        return {
            (u, v) for u in reachable
            for v in subgraph.successors(u)
            if v in protected
        }

    @staticmethod
    def _cut_cost(graph: nx.DiGraph, edges: Set[Edge]) -> float:
        return sum(float(graph[u][v].get('cost', 1.0)) for u, v in edges)

    def minimum_cut_candidate(self, subgraph: nx.DiGraph, attacker: str, target: str) -> Optional[CutCandidate]:
        if attacker not in subgraph or target not in subgraph or not nx.has_path(subgraph, attacker, target):
            return None
        flow_value, partitions = nx.minimum_cut(subgraph, attacker, target, capacity='cost')
        reachable, protected = partitions
        edges = self._cut_edges(subgraph, reachable, protected)
        return CutCandidate(
            target=target,
            flow_value=float(flow_value),
            cut_edges=edges,
            cut_cost=self._cut_cost(subgraph, edges),
            reachable_nodes=set(reachable),
            protected_nodes=set(protected),
        )

    @staticmethod
    def validate_global(graph: nx.DiGraph, attacker: str, targets: Sequence[str], cut_edges: Set[Edge]) -> Tuple[bool, List[str]]:
        g = graph.copy()
        g.remove_edges_from(cut_edges)
        exposed = [t for t in targets if t in g and attacker in g and nx.has_path(g, attacker, t)]
        return len(exposed) == 0, exposed

    def greedy_select(self, local_graph: nx.DiGraph, attacker: str, targets: Sequence[str], budget: float):
        candidates: Dict[str, CutCandidate] = {}
        for target in targets:
            candidate = self.minimum_cut_candidate(local_graph, attacker, target)
            if candidate:
                candidates[target] = candidate

        remaining = set(candidates)
        selected: Set[Edge] = set()
        protected_assets: Set[str] = set()
        history: List[Dict] = []
        total_cost = 0.0

        while remaining:
            best = None
            for target in remaining:
                c = candidates[target]
                incremental = c.cut_edges - selected
                inc_cost = self._cut_cost(local_graph, incremental)
                if total_cost + inc_cost > budget:
                    continue
                # For fixed-value targets, choose the minimum incremental disruption.
                key = (inc_cost, target)
                if best is None or key < best[0]:
                    best = (key, target, incremental, inc_cost, c)

            if best is None:
                break

            _, target, incremental, inc_cost, candidate = best
            selected.update(incremental)
            total_cost += inc_cost
            protected_assets.add(target)
            remaining.remove(target)
            history.append({
                'target': target,
                'incremental_edges': sorted(incremental),
                'incremental_cost': inc_cost,
                'total_cost': total_cost,
                'flow_value': candidate.flow_value,
            })

        return selected, total_cost, sorted(protected_assets), sorted(remaining), history

    def analyze_incident(
        self,
        attacker: str,
        targets: Sequence[str],
        budget: float,
        initial_radius: int = 2,
        max_radius: int = 5,
        attack_path: Optional[List[str]] = None,
    ) -> IncidentResult:
        if budget < 0:
            raise ValueError('budget must be non-negative')
        if initial_radius < 0 or max_radius < initial_radius:
            raise ValueError('invalid radius bounds')

        targets = list(dict.fromkeys(targets))
        phase: Dict[str, float] = {}
        candidate_history: List[Dict] = []
        current_radius = initial_radius
        expanded = False
        final_selected: Set[Edge] = set()
        final_cost = 0.0
        final_protected: List[str] = []
        final_unprotected: List[str] = list(targets)
        final_candidate: Optional[CutCandidate] = None
        final_validation = False
        validation_message = 'No analysis performed.'

        # A supplied path is for demo visualization only; algorithmic decisions use the graph.
        while True:
            t0 = time.perf_counter()
            local_graph = nx.ego_graph(self.graph, attacker, radius=current_radius, undirected=False)
            phase['neighborhood_extraction_ms'] = (time.perf_counter() - t0) * 1000

            t0 = time.perf_counter()
            selected, total_cost, protected, unprotected, history = self.greedy_select(
                local_graph, attacker, targets, budget
            )
            phase['optimization_ms'] = (time.perf_counter() - t0) * 1000
            candidate_history.append({'radius': current_radius, 'greedy': history})

            # For the primary single-target view, expose the min-cut candidate.
            primary = self.minimum_cut_candidate(local_graph, attacker, targets[0]) if targets else None

            t0 = time.perf_counter()
            contained, exposed = self.validate_global(self.graph, attacker, targets, selected)
            phase['global_validation_ms'] = (time.perf_counter() - t0) * 1000

            final_selected = selected
            final_cost = total_cost
            final_protected = protected
            final_unprotected = exposed or unprotected
            final_candidate = primary
            final_validation = contained

            if contained:
                validation_message = 'Global reachability validation passed.'
                break
            if current_radius >= max_radius:
                validation_message = 'Maximum radius reached; global containment could not be verified.'
                break
            current_radius += 1
            expanded = True

        local_graph = nx.ego_graph(self.graph, attacker, radius=current_radius, undirected=False)
        return IncidentResult(
            incident_detected=attacker in self.graph and any(t in self.graph for t in targets),
            attacker=attacker,
            targets=targets,
            initial_radius=initial_radius,
            final_radius=current_radius,
            max_radius=max_radius,
            expanded=expanded,
            local_nodes=local_graph.number_of_nodes(),
            local_edges=local_graph.number_of_edges(),
            global_nodes=self.graph.number_of_nodes(),
            global_edges=self.graph.number_of_edges(),
            locality_vertex_ratio=local_graph.number_of_nodes() / max(1, self.graph.number_of_nodes()),
            locality_edge_ratio=local_graph.number_of_edges() / max(1, self.graph.number_of_edges()),
            max_flow=final_candidate.flow_value if final_candidate else None,
            min_cut_cost=final_candidate.cut_cost if final_candidate else None,
            cut_edges=sorted(final_candidate.cut_edges) if final_candidate else [],
            selected_edges=sorted(final_selected),
            disruption_cost=final_cost,
            protected_assets=final_protected,
            unprotected_assets=final_unprotected,
            global_containment=final_validation,
            validation_message=validation_message,
            phase_timings_ms=phase,
            attack_path=attack_path or [],
            candidate_history=candidate_history,
        )
