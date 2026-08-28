import time
import networkx as nx
from typing import Dict, Any
from containment.containment_engine import ContainmentEngine

class SystemEvaluator:
    """
    Races ShadowCut against traditional full-graph recomputation baselines 
    to generate reproducible latency and accuracy benchmarks.
    """
    def __init__(self, engine: ContainmentEngine):
        self.engine = engine

    def run_benchmark(self, global_graph: nx.DiGraph, attacker: str, asset: str, radius: int = 2) -> Dict[str, Any]:
        """Runs both approaches side-by-side and returns the comparative metrics."""
        results = {}

        # --- BASELINE: Full Graph Recomputation ---
        start_baseline = time.perf_counter()
        # We use the internal single-cut helper to bypass the budget logic for a pure 1-to-1 comparison
        baseline_cost, baseline_partitions = nx.minimum_cut(global_graph, attacker, asset, capacity='cost')
        baseline_time = (time.perf_counter() - start_baseline) * 1000
        
        results['baseline_time_ms'] = baseline_time
        results['baseline_cost'] = baseline_cost

        # --- SHADOWCUT: Bounded Neighborhood ---
        start_shadow = time.perf_counter()
        
        # 1. Extract
        subgraph = nx.ego_graph(global_graph, attacker, radius=radius, undirected=False)
        
        # 2. Compute Cut on Subgraph
        shadow_cost = 0.0
        if asset in subgraph and nx.has_path(subgraph, attacker, asset):
            shadow_cost, _ = nx.minimum_cut(subgraph, attacker, asset, capacity='cost')
            
        shadow_time = (time.perf_counter() - start_shadow) * 1000
        
        results['shadow_time_ms'] = shadow_time
        results['shadow_cost'] = shadow_cost
        
        return results
