import time
import random
from graph.graph_state import EnterpriseGraph
from containment.containment_engine import ContainmentEngine
from evaluation.evaluator import SystemEvaluator

def generate_enterprise_noise(graph_system: EnterpriseGraph, num_nodes: int = 1000, num_edges: int = 3000):
    """Injects background network traffic to simulate a massive enterprise environment."""
    nodes = [f"HOST_{i}" for i in range(num_nodes)]
    
    for _ in range(num_edges):
        src = random.choice(nodes)
        dst = random.choice(nodes)
        if src != dst:
            graph_system.ingest_auth_event(src, dst, timestamp=time.time(), disruption_cost=1.0)

def run_pipeline():
    print("=== ShadowCut: Experimental Benchmark ===")
    sys_graph = EnterpriseGraph()
    engine = ContainmentEngine()
    evaluator = SystemEvaluator(engine)
    
    # 1. Build the target lateral movement path (The actual attack)
    attacker = "COMPROMISED_PC"
    asset = "CRITICAL_VAULT"
    sys_graph.ingest_auth_event(attacker, "PIVOT_1", timestamp=time.time(), disruption_cost=1.0)
    sys_graph.ingest_auth_event("PIVOT_1", asset, timestamp=time.time(), disruption_cost=5.0)
    sys_graph.ingest_auth_event(attacker, "PIVOT_2", timestamp=time.time(), disruption_cost=2.0)
    sys_graph.ingest_auth_event("PIVOT_2", asset, timestamp=time.time(), disruption_cost=3.0)
    
    # 2. Inject massive background noise to stress-test the algorithms
    print("[*] Generating enterprise background traffic (1,000 nodes, 3,000 edges)...")
    generate_enterprise_noise(sys_graph, num_nodes=1000, num_edges=3000)
    
    sys_graph.print_graph_metrics(sys_graph.G, "Global Enterprise Graph")
    
    # 3. Execute the Benchmark
    print("\n[*] Racing ShadowCut vs. Full-Graph Baseline...")
    metrics = evaluator.run_benchmark(sys_graph.G, attacker, asset, radius=2)
    
    print("\n=== Experimental Results ===")
    print(f"Baseline Execution Latency : {metrics['baseline_time_ms']:.4f} ms")
    print(f"ShadowCut Execution Latency: {metrics['shadow_time_ms']:.4f} ms")
    
    speedup = metrics['baseline_time_ms'] / max(metrics['shadow_time_ms'], 0.0001)
    print(f"\n[+] ShadowCut is {speedup:.2f}x faster.")
    
    print(f"\nMathematical Accuracy Check:")
    print(f"Baseline Cost: {metrics['baseline_cost']} | ShadowCut Cost: {metrics['shadow_cost']}")
    if metrics['baseline_cost'] == metrics['shadow_cost']:
        print("[SUCCESS] ShadowCut achieved mathematically identical containment at a fraction of the compute cost.")
    else:
        print("[WARNING] Topological mismatch. The bounded radius may be too small.")

if __name__ == "__main__":
    run_pipeline()
