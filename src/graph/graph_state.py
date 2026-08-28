import networkx as nx
from typing import Optional

class EnterpriseGraph:
    """
    Manages the dynamic enterprise authentication graph, handles 
    localized bounded-neighborhood extraction, and maintains temporal sparsity.
    """
    def __init__(self):
        self.G = nx.DiGraph()

    def ingest_auth_event(self, source: str, target: str, timestamp: float, disruption_cost: float = 1.0) -> None:
        """
        Inserts or updates an authentication edge with the latest timestamp.
        """
        if self.G.has_edge(source, target):
            self.G[source][target]['cost'] += disruption_cost
            self.G[source][target]['last_seen'] = timestamp
        else:
            self.G.add_edge(source, target, cost=disruption_cost, last_seen=timestamp)

    def prune_stale_edges(self, current_time: float, max_age: float) -> int:
        """
        Acts as a temporal sparsifier by removing edges older than max_age.
        Returns the number of edges pruned.
        """
        stale_edges = []
        for u, v, data in self.G.edges(data=True):
            if (current_time - data['last_seen']) > max_age:
                stale_edges.append((u, v))
                
        for u, v in stale_edges:
            self.G.remove_edge(u, v)
            
        # Optional: Clean up isolated nodes to free memory
        isolated = list(nx.isolates(self.G))
        self.G.remove_nodes_from(isolated)
        
        return len(stale_edges)

    def extract_neighborhood(self, alert_node: str, radius: int = 2) -> Optional[nx.DiGraph]:
        if alert_node not in self.G:
            return None
        return nx.ego_graph(self.G, alert_node, radius=radius, undirected=False)

    def print_graph_metrics(self, graph: nx.DiGraph, name: str = "Graph") -> None:
        print(f"--- {name} Metrics ---")
        print(f"Nodes: {graph.number_of_nodes()}")
        print(f"Edges: {graph.number_of_edges()}")
        print("-" * 22)
