import time
import random
import matplotlib.pyplot as plt
import csv
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from graph.graph_state import EnterpriseGraph
from containment.containment_engine import ContainmentEngine
from evaluation.evaluator import SystemEvaluator

def run_scaling_benchmark():
    print("=== ShadowCut: Automated Scaling Benchmark ===")
    
    engine = ContainmentEngine()
    evaluator = SystemEvaluator(engine)
    
    # Test sizes: 1000, 2000, 3000, 4000, 5000 nodes
    # We keep the edge density roughly proportional (3 edges per node)
    sizes = [1000, 2000, 3000, 4000, 5000]
    
    baseline_times = []
    shadowcut_times = []
    
    attacker = "COMPROMISED_PC"
    asset = "CRITICAL_VAULT"
    
    for size in sizes:
        print(f"[*] Building enterprise graph with {size} nodes...")
        sys_graph = EnterpriseGraph()
        
        # 1. Inject Attack Path
        sys_graph.ingest_auth_event(attacker, "PIVOT_1", timestamp=time.time(), disruption_cost=1.0)
        sys_graph.ingest_auth_event("PIVOT_1", asset, timestamp=time.time(), disruption_cost=5.0)
        
        # 2. Inject Background Noise
        nodes = [f"HOST_{i}" for i in range(size)]
        edges_to_inject = size * 3
        for _ in range(edges_to_inject):
            src, dst = random.sample(nodes, 2)
            sys_graph.ingest_auth_event(src, dst, timestamp=time.time(), disruption_cost=1.0)
            
        # 3. Race!
        metrics = evaluator.run_benchmark(sys_graph.G, attacker, asset, radius=2)
        
        baseline_times.append(metrics['baseline_time_ms'])
        shadowcut_times.append(metrics['shadow_time_ms'])
        
        print(f"    -> Baseline: {metrics['baseline_time_ms']:.2f} ms | ShadowCut: {metrics['shadow_time_ms']:.2f} ms")

    # --- SAVE RESULTS ---
    print("\n[*] Exporting results...")
    
    # Save CSV
    with open("data/scaling_results.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Graph_Size", "Baseline_Latency_ms", "ShadowCut_Latency_ms"])
        for i in range(len(sizes)):
            writer.writerow([sizes[i], baseline_times[i], shadowcut_times[i]])
            
    # Save Chart
    plt.figure(figsize=(10, 6))
    plt.plot(sizes, baseline_times, marker='o', color='red', label='Full-Graph Recomputation (Baseline)', linewidth=2)
    plt.plot(sizes, shadowcut_times, marker='s', color='blue', label='ShadowCut (Bounded Subgraph)', linewidth=2)
    
    plt.title('Containment Algorithm Scaling: ShadowCut vs Baseline', fontsize=14)
    plt.xlabel('Enterprise Network Size (Nodes)', fontsize=12)
    plt.ylabel('Execution Latency (ms)', fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend(fontsize=12)
    plt.tight_layout()
    
    chart_path = "data/scaling_chart.png"
    plt.savefig(chart_path, dpi=300)
    
    print(f"[SUCCESS] CSV saved to data/scaling_results.csv")
    print(f"[SUCCESS] High-resolution chart saved to {chart_path}")

if __name__ == "__main__":
    run_scaling_benchmark()
