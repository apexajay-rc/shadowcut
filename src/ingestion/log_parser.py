import csv
import os
from typing import Any

def generate_synthetic_lanl(filepath: str) -> None:
    if os.path.exists(filepath): return
    
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    logs = [
        "time,source,destination,status",
        "100,USER_1,WORKSTATION_A,Success",      # Very old event
        "150,USER_1,WORKSTATION_A,Success",      # Very old event
        "3000,WORKSTATION_A,SERVER_DB,Success",  # Recent event
        "3050,WORKSTATION_B,SERVER_DB,Success",  # Recent event
        "3100,COMPROMISED_PC,WORKSTATION_A,Success", # Recent attack pivot
        "3150,COMPROMISED_PC,WORKSTATION_B,Success"  # Recent attack pivot
    ]
    with open(filepath, 'w', newline='') as f:
        f.write("\n".join(logs) + "\n")

def ingest_csv_to_graph(filepath: str, graph_system: Any) -> int:
    event_count = 0
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['status'] == 'Success':
                # Parse timestamp and ingest
                timestamp = float(row['time'])
                graph_system.ingest_auth_event(
                    row['source'], 
                    row['destination'], 
                    timestamp=timestamp, 
                    disruption_cost=1.0
                )
                event_count += 1
    return event_count
