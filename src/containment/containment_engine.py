import networkx as nx
from typing import List, Set, Tuple, Dict

class ContainmentEngine:
    """
    Executes real-time graph-cut algorithms and greedy set-cover approximations 
    to isolate compromised hosts under strict disruption budgets.
    """
    def __init__(self):
        pass

    def _get_single_min_cut(self, subgraph: nx.DiGraph, attacker_node: str, asset: str) -> Set[Tuple[str, str]]:
        """Helper to get the candidate edges for a single asset."""
        if not nx.has_path(subgraph, attacker_node, asset):
            return set()
        
        _, partitions = nx.minimum_cut(subgraph, attacker_node, asset, capacity='cost')
        reachable, protected = partitions
        
        edges = set()
        for u in reachable:
            for v in subgraph.successors(u):
                if v in protected:
                    edges.add((u, v))
        return edges

    def compute_budgeted_containment(self, subgraph: nx.DiGraph, attacker_node: str, 
                                     critical_assets: List[str], budget: float) -> Tuple[float, Set[Tuple[str, str]], List[str]]:
        """
        Applies a greedy weighted set-cover approximation to select the most cost-effective 
        containment actions without exceeding the disruption budget.
        Returns: (Total Cost, Selected Edges, List of Unprotected Assets)
        """
        # 1. Map each asset to its required Min-Cut set of edges
        asset_to_cuts = {}
        for asset in critical_assets:
            cuts = self._get_single_min_cut(subgraph, attacker_node, asset)
            if cuts: # Only track assets that actually have an attack path
                asset_to_cuts[asset] = cuts

        unprotected_assets = set(asset_to_cuts.keys())
        selected_edges = set()
        current_cost = 0.0

        # 2. Greedy Loop: Greedily protect ASSETS based on incremental edge costs
        while unprotected_assets:
            best_asset = None
            best_ratio = -1.0
            best_incremental_cost = 0.0
            best_incremental_edges = set()

            for asset in unprotected_assets:
                # What new edges do we need to cut to protect THIS asset?
                required_edges = asset_to_cuts[asset]
                incremental_edges = required_edges - selected_edges
                
                # Calculate cost of these new edges
                incremental_cost = sum(subgraph[u][v]['cost'] for u, v in incremental_edges)
                
                # If it's already protected by previous cuts, cost is 0. Automatic win.
                if incremental_cost == 0:
                    best_ratio = float('inf')
                    best_asset = asset
                    best_incremental_cost = 0
                    best_incremental_edges = set()
                    break 
                
                if current_cost + incremental_cost > budget:
                    continue # We cannot afford to protect this asset
                    
                ratio = 1.0 / incremental_cost 
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_asset = asset
                    best_incremental_cost = incremental_cost
                    best_incremental_edges = incremental_edges

            # If no valid asset can be protected within the remaining budget, halt.
            if best_asset is None:
                break 
                
            # Apply the best asset choice
            selected_edges.update(best_incremental_edges)
            current_cost += best_incremental_cost
            unprotected_assets.remove(best_asset)

        return current_cost, selected_edges, list(unprotected_assets)
