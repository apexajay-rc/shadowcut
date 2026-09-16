import networkx as nx

ATTACKER = "PC-07"
PRIMARY_TARGET = "VAULT"
PROTECTED_ASSETS = ["VAULT", "FIN-01", "ID-01"]
ATTACK_PATH = ["PC-07", "WEB-01", "APP-01", "DB-01", "FIN-01", "VAULT"]


def build_demo_graph() -> nx.DiGraph:
    g = nx.DiGraph()
    for i in range(28):
        g.add_node(f"PC-{i+1:02d}", kind="pc")
    for name in ["WEB-01", "APP-01", "DB-01", "ID-01", "FIN-01", "FILE-01", "VAULT"]:
        g.add_node(name, kind="server")
    for critical in ["VAULT", "FIN-01", "ID-01"]:
        g.nodes[critical]["kind"] = "critical"

    normal_edges = [
        ("PC-01", "WEB-01"), ("PC-02", "WEB-01"), ("PC-03", "WEB-01"),
        ("PC-04", "APP-01"), ("PC-05", "APP-01"), ("PC-06", "APP-01"),
        ("WEB-01", "APP-01"), ("APP-01", "DB-01"), ("APP-01", "ID-01"),
        ("DB-01", "FIN-01"), ("FIN-01", "VAULT"), ("ID-01", "FILE-01"),
        ("FILE-01", "VAULT"), ("PC-10", "FILE-01"), ("PC-11", "FIN-01"),
        ("PC-12", "DB-01"), ("PC-13", "ID-01"), ("PC-14", "WEB-01"),
    ]
    for u, v in normal_edges:
        g.add_edge(u, v, cost=1.0, source="normal")

    # Main lateral-movement chain.
    for u, v, cost in zip(ATTACK_PATH[:-1], ATTACK_PATH[1:], [1.0, 1.0, 2.0, 3.0, 5.0]):
        g.add_edge(u, v, cost=cost, source="attack")

    # Deliberately longer bypass. It forces a 2-hop local solution to be validated globally.
    bypass = ["PC-07", "PC-08", "FILE-01", "VAULT"]
    for u, v, cost in zip(bypass[:-1], bypass[1:], [1.0, 2.0, 6.0]):
        g.add_edge(u, v, cost=cost, source="bypass")

    # Direct route to another protected asset for the multi-target greedy stage.
    g.add_edge("PC-07", "ID-01", cost=2.0, source="attack")
    return g
