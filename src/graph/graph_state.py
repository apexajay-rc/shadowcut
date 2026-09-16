import networkx as nx
from typing import Optional

class EnterpriseGraph:
    def __init__(self):
        self.G = nx.DiGraph()

    def ingest_auth_event(self, source: str, target: str, timestamp: float,
                          disruption_cost: float = 1.0) -> None:
        if source == target:
            return
        if disruption_cost < 0:
            raise ValueError("disruption_cost must be non-negative")
        # Keep relationship cost as an explicit operational value. Repeated
        # observations increase activity count rather than silently changing cost.
        if self.G.has_edge(source, target):
            data = self.G[source][target]
            data['observations'] = data.get('observations', 1) + 1
            data['last_seen'] = max(data.get('last_seen', timestamp), timestamp)
        else:
            self.G.add_edge(
                source, target,
                cost=float(disruption_cost),
                observations=1,
                last_seen=float(timestamp),
            )

    def prune_stale_edges(self, current_time: float, max_age: float) -> int:
        if max_age < 0:
            raise ValueError("max_age must be non-negative")
        stale = [
            (u, v) for u, v, data in self.G.edges(data=True)
            if current_time - data['last_seen'] > max_age
        ]
        self.G.remove_edges_from(stale)
        self.G.remove_nodes_from(list(nx.isolates(self.G)))
        return len(stale)

    def extract_neighborhood(self, alert_node: str, radius: int = 2) -> Optional[nx.DiGraph]:
        if alert_node not in self.G:
            return None
        if radius < 0:
            raise ValueError("radius must be non-negative")
        return nx.ego_graph(self.G, alert_node, radius=radius, undirected=False)
