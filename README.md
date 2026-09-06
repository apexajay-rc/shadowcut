<div align="center">

# ShadowCut

### **Bounded-Neighborhood Graph-Cut Optimization for Lateral Movement Containment**

<p>
  <img src="https://img.shields.io/badge/status-research%20prototype-7c3aed?style=for-the-badge" alt="Research Prototype"/>
  <img src="https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/NetworkX-graph%20optimization-0f766e?style=for-the-badge" alt="NetworkX"/>
  <img src="https://img.shields.io/badge/Streamlit-security%20console-ff4b4b?style=for-the-badge&logo=streamlit&logoColor=white" alt="Streamlit"/>
</p>

<p>
  <strong>Stop treating the entire enterprise graph as the attack surface.</strong><br/>
  ShadowCut investigates whether lateral-movement containment can be localized to a bounded attack neighborhood without sacrificing containment quality.
</p>

</div>

---

## The Idea

Enterprise networks are not small.

Every authentication event adds another relationship to an evolving graph. When a host is compromised, the security problem is not simply:

> **"Is this host malicious?"**

It is:

> **"Which relationships should be disrupted so that the attacker cannot reach a critical asset, while minimizing operational disruption?"**

ShadowCut frames that problem as **graph-cut optimization** and investigates a locality assumption:

```mermaid
flowchart LR
    A["Enterprise Authentication Events"] --> B["Dynamic Enterprise Graph"]
    B --> C["Suspected Compromised Host"]
    C --> D["Bounded k-Hop Neighborhood"]
    D --> E["Minimum s-t Cut"]
    E --> F["Budget-Constrained Containment"]
    F --> G["Recommended Connections to Sever"]

    style A fill:#111827,stroke:#64748b,color:#fff
    style B fill:#172554,stroke:#3b82f6,color:#fff
    style C fill:#450a0a,stroke:#ef4444,color:#fff
    style D fill:#312e81,stroke:#8b5cf6,color:#fff
    style E fill:#164e63,stroke:#06b6d4,color:#fff
    style F fill:#422006,stroke:#f59e0b,color:#fff
    style G fill:#14532d,stroke:#22c55e,color:#fff
```

The central question is:

$$
\boxed{
\text{Can local graph optimization achieve global-quality containment at substantially lower latency?}
}
$$

---

## Why ShadowCut?

A conventional approach can repeatedly perform graph analysis against the **full enterprise topology**.

ShadowCut instead constructs:

$$
G_k(s)
$$

where:

- $G$ = global enterprise graph
- $s$ = suspected compromised node
- $k$ = neighborhood radius
- $G_k(s)$ = bounded neighborhood around $s$

The containment problem is then evaluated on $G_k(s)$.

```mermaid
graph TD
    subgraph GLOBAL["Global Enterprise Graph G"]
        S["🔴 COMPROMISED HOST"]
        A["Host A"]
        B["Host B"]
        C["Host C"]
        D["Host D"]
        E["Host E"]
        F["Host F"]
        X["Host X"]
        Y["Host Y"]
        T["🟢 CRITICAL ASSET"]

        S --> A
        S --> B
        A --> C
        B --> D
        C --> T
        D --> T
        E --> F
        F --> X
        X --> Y
        Y --> T
    end

    subgraph LOCAL["Bounded Neighborhood Gₖ(s)"]
        S2["🔴 COMPROMISED"]
        P1["Pivot 1"]
        P2["Pivot 2"]
        T2["🟢 CRITICAL ASSET"]

        S2 --> P1
        S2 --> P2
        P1 --> T2
        P2 --> T2
    end

    GLOBAL -. "extract k-hop neighborhood" .-> LOCAL

    style S fill:#ef4444,color:#fff
    style T fill:#22c55e,color:#fff
    style S2 fill:#ef4444,color:#fff
    style T2 fill:#22c55e,color:#fff
    style GLOBAL fill:#0f172a,stroke:#334155,color:#fff
    style LOCAL fill:#111827,stroke:#7c3aed,color:#fff
```

---

## Core Optimization Model

For a directed enterprise graph:

$$
G=(V,E)
$$

each edge $e\in E$ has a disruption cost:

$$
w(e)\geq0
$$

Given a compromised node $s$ and critical asset $t$, ShadowCut seeks a set of edges $C$ whose removal disconnects $s$ from $t$:

$$
\min_{C\subseteq E}
\sum_{e\in C}w(e)
$$

subject to:

$$
s\not\leadsto t
$$

In other words:

> **Find the cheapest set of relationships that prevents the compromised host from reaching the protected asset.**

### Disruption Budget

Containment also operates under an operational budget $B$:

$$
\sum_{e\in C}w(e)\leq B
$$

This introduces a practical trade-off:

$$
\boxed{
\text{Security Isolation}
\quad\leftrightarrow\quad
\text{Operational Disruption}
}
$$

The system therefore does not blindly maximize isolation. It attempts to determine what can be contained **within the specified disruption budget**.

---

# Architecture

![ShadowCut Architecture](data/shadowcut-architecture.svg)

```mermaid
flowchart TB
    subgraph INGEST["01 · INGESTION"]
        L["Authentication / Network Events"]
        P["CSV Event Parser"]
    end

    subgraph GRAPH["02 · GRAPH STATE"]
        G["EnterpriseGraph"]
        T["Temporal Edge State"]
        S["Stale Edge Pruning"]
        N["k-Hop Neighborhood Extraction"]
    end

    subgraph OPT["03 · CONTAINMENT"]
        MC["Minimum s-t Cut"]
        BC["Budget-Constrained Selection"]
        C["Containment Recommendations"]
    end

    subgraph EVAL["04 · EVALUATION"]
        B["Benchmark Suite"]
        BL["Full-Graph Baseline"]
        SC["ShadowCut Local Computation"]
    end

    subgraph UI["05 · OPERATIONS UI"]
        D["Streamlit Security Console"]
        V["Threat Neighborhood Visualization"]
    end

    L --> P --> G
    G --> T
    G --> S
    G --> N
    N --> MC --> BC --> C

    G --> BL
    N --> SC
    BL --> B
    SC --> B

    C --> D
    N --> V
    C --> V

    style INGEST fill:#111827,stroke:#475569,color:#fff
    style GRAPH fill:#172554,stroke:#3b82f6,color:#fff
    style OPT fill:#312e81,stroke:#8b5cf6,color:#fff
    style EVAL fill:#164e63,stroke:#06b6d4,color:#fff
    style UI fill:#422006,stroke:#f59e0b,color:#fff
```

---

# How ShadowCut Works

### 1. Build the graph

Successful authentication events become directed graph edges.

```text
USER_A ───────→ WORKSTATION_1
                    │
                    ▼
                SERVER_DB
```

Edges maintain a timestamp and disruption cost.

### 2. Maintain temporal state

Edges can become stale and are pruned after a configurable age.

```mermaid
flowchart LR
    A["New authentication event"] --> B["Update edge"]
    B --> C["Refresh last_seen"]
    C --> D{"Older than max_age?"}
    D -- "No" --> E["Keep edge"]
    D -- "Yes" --> F["Prune edge"]

    style A fill:#172554,stroke:#3b82f6,color:#fff
    style B fill:#312e81,stroke:#8b5cf6,color:#fff
    style C fill:#164e63,stroke:#06b6d4,color:#fff
    style E fill:#14532d,stroke:#22c55e,color:#fff
    style F fill:#450a0a,stroke:#ef4444,color:#fff
```

### 3. Localize the threat

When a compromised host is identified, ShadowCut extracts a bounded neighborhood around it.

### 4. Compute containment

The localized graph is passed to the containment engine.

For a single target, the system computes a minimum $s$-$t$ cut.

For multiple targets, the current implementation applies a greedy budget-constrained selection procedure over candidate cuts.

### 5. Return actionable recommendations

The system reports:

- selected edges
- containment cost
- remaining exposed assets
- extraction latency
- cut-computation latency

---

# Example Attack Path

Consider an attacker with two possible routes to a critical asset:

```mermaid
graph LR
    A["🔴 COMPROMISED_PC"]
    P1["PIVOT_1"]
    P2["PIVOT_2"]
    T["🟢 CRITICAL_VAULT"]

    A -->|"cost = 1"| P1
    A -->|"cost = 2"| P2
    P1 -->|"cost = 5"| T
    P2 -->|"cost = 3"| T

    style A fill:#ef4444,color:#fff,stroke:#991b1b
    style T fill:#22c55e,color:#fff,stroke:#166534
    style P1 fill:#38bdf8,color:#0f172a
    style P2 fill:#38bdf8,color:#0f172a
```

The containment engine reasons over the available cuts rather than simply isolating the entire host/network.

This is the underlying principle:

$$
\text{Contain the attack path}
\neq
\text{Disconnect the entire environment}
$$

---

# Repository Structure

```text
shadowcut/
│
├── data/
│   ├── shadowcut-architecture.svg
│   ├── synthetic_lanl.csv
│   ├── scaling_results.csv
│   └── scaling_chart.png
│
├── src/
│   ├── containment/
│   │   └── containment_engine.py
│   │
│   ├── evaluation/
│   │   ├── benchmark_suite.py
│   │   └── evaluator.py
│   │
│   ├── graph/
│   │   └── graph_state.py
│   │
│   ├── ingestion/
│   │   └── log_parser.py
│   │
│   ├── ui/
│   │   └── dashboard.py
│   │
│   └── main.py
│
└── README.md
```

---

# Experimental Results

The initial scaling experiment compares:

### Baseline

Minimum cut computed over the complete enterprise graph.

### ShadowCut

Bounded-neighborhood extraction followed by minimum-cut computation.

| Graph Size | Full-Graph Baseline | ShadowCut |
|---:|---:|---:|
| 1,000 nodes | 15.68 ms | **0.70 ms** |
| 2,000 nodes | 53.76 ms | **0.23 ms** |
| 3,000 nodes | 78.67 ms | **0.24 ms** |
| 4,000 nodes | 138.76 ms | **0.27 ms** |
| 5,000 nodes | 173.96 ms | **0.28 ms** |

### Scaling behavior

```mermaid
xychart-beta
    title "Containment Computation Latency"
    x-axis "Graph Size" [1000, 2000, 3000, 4000, 5000]
    y-axis "Latency (ms)" 0 --> 180
    line "Full Graph" [15.68, 53.76, 78.67, 138.76, 173.96]
    line "ShadowCut" [0.70, 0.23, 0.24, 0.27, 0.28]
```

> **Important:** these are preliminary synthetic results. They demonstrate the behavior of the current prototype under the benchmark's topology and attack construction; they do not by themselves establish production-scale enterprise performance.

---

# The Research Question

ShadowCut is built around a locality hypothesis.

Let:

$$
T_G = \text{time required to compute containment on }G
$$

and:

$$
T_k = \text{time required to compute containment on }G_k(s)
$$

The desired property is:

$$
T_k \ll T_G
$$

while maintaining high containment fidelity:

$$
F_k =
\frac{
\text{local decisions matching global decisions}
}{
\text{total scenarios}
}
$$

The interesting question is therefore the **latency–fidelity trade-off**:

```mermaid
quadrantChart
    title Locality Trade-off
    x-axis "Low containment fidelity" --> "High containment fidelity"
    y-axis "Low computational efficiency" --> "High computational efficiency"
    quadrant-1 "Target region"
    quadrant-2 "Too expensive"
    quadrant-3 "Poor solution"
    quadrant-4 "Fast but unsafe"
```

The research problem is not merely whether local computation is faster.

It is:

> **How small can the analyzed neighborhood become before containment decisions diverge from the global optimum?**

---

# Research Directions

ShadowCut currently provides the foundation for investigating:

| Direction | Research Question |
|---|---|
| **Adaptive Radius** | Can $k$ be selected dynamically from attack topology? |
| **Containment Fidelity** | When does the local cut equal the global cut? |
| **Temporal Graphs** | How does graph staleness affect containment? |
| **Large-Scale Graphs** | Does locality continue to provide benefits at $10^5$–$10^6+$ nodes? |
| **Multi-Asset Protection** | How should multiple critical assets be optimized jointly? |
| **Dynamic Flow** | Can incremental min-cut algorithms reduce repeated recomputation? |
| **Operational Cost** | How should disruption cost reflect actual enterprise dependencies? |

---

# Current Limitations

<details>
<summary><strong>Research limitations</strong></summary>

The current repository is an experimental research prototype.

### Synthetic evaluation

The current scaling benchmark uses generated graph topology and a deliberately constructed attack path.

### Dataset scope

The included `synthetic_lanl.csv` is a small synthetic dataset inspired by authentication-log structure; it is not a complete LANL authentication dataset.

### Fixed neighborhood radius

The current implementation accepts a radius parameter rather than learning or adapting the radius based on attack topology.

### Prototype containment

ShadowCut currently recommends connections to sever. It does not directly modify firewalls, NAC policies, SDN rules, or endpoint isolation state.

### Graph abstraction

Authentication relationships are represented as graph edges with disruption costs. Real enterprise environments contain additional semantics such as identity privilege, service dependencies, role relationships, and business criticality.

### Multi-target optimization

The current multi-asset procedure is a greedy heuristic and should not be interpreted as a globally optimal solution to the general multi-terminal containment problem.

</details>

---

# Technology Stack

<div align="center">

| Component | Technology |
|---|---|
| Language | **Python** |
| Graph Engine | **NetworkX** |
| Visualization | **Matplotlib** |
| Security Console | **Streamlit** |
| Data | **CSV / Authentication Events** |
| Optimization | **Minimum s-t Cut + Greedy Budgeted Selection** |

</div>

---

# Quick Start

## 1. Clone

```bash
git clone https://github.com/apexajay-rc/shadowcut.git
cd shadowcut
```

## 2. Install dependencies

```bash
pip install networkx streamlit matplotlib
```

## 3. Run the experimental pipeline

```bash
python src/main.py
```

## 4. Run the scaling benchmark

```bash
python src/evaluation/benchmark_suite.py
```

## 5. Launch the security console

```bash
streamlit run src/ui/dashboard.py
```

---

# Security Console

The Streamlit interface exposes the core research parameters:

```text
┌───────────────────────────────────────────────────────────────┐
│                 SHADOWCUT SECURITY CONSOLE                    │
├──────────────────────┬────────────────────────────────────────┤
│ THREAT PARAMETERS    │ CONTAINMENT EXECUTION                  │
│                      │                                        │
│ Suspected Host       │ Extraction Latency       0.24 ms       │
│ COMPROMISED_PC       │                                        │
│                      │ Min-Cut Latency          0.18 ms       │
│ Critical Asset       │                                        │
│ CRITICAL_VAULT       │ Disruption Cost           3 / 5        │
│                      │                                        │
│ Budget               │ Recommended Connections               │
│ ███████░░ 5.0        │ COMPROMISED_PC → PIVOT_2              │
│                      │                                        │
│ Radius               │ [ BOUNDED THREAT NEIGHBORHOOD ]       │
│ 2 hops               │                                        │
└──────────────────────┴────────────────────────────────────────┘
```

The dashboard visualizes the bounded threat neighborhood and highlights recommended containment edges.

---

# What ShadowCut Is — and Is Not

### ShadowCut **is**

- A graph-based lateral movement containment prototype.
- A minimum-cut based containment engine.
- A bounded-neighborhood graph optimization approach.
- A disruption-budget-aware decision system.
- An experimental platform for studying locality versus containment fidelity.

### ShadowCut **is not yet**

- A production EDR.
- A complete SIEM.
- An autonomous firewall controller.
- A validated enterprise-scale containment platform.
- A complete implementation of a dynamic distributed graph engine.

This distinction is intentional.

---

# Research Contribution

The central idea investigated by ShadowCut can be summarized as:

$$
\boxed{
\text{Global Enterprise Graph}
\rightarrow
\text{Localized Attack Neighborhood}
\rightarrow
\text{Graph-Cut Containment}
}
$$

The intended contribution is not the invention of minimum-cut algorithms.

Instead, ShadowCut investigates whether **graph locality can be exploited to make lateral-movement containment computationally cheaper while retaining acceptable containment fidelity and respecting operational disruption constraints**.

That creates a measurable systems/security research problem:

$$
\underbrace{\text{Latency}}_{\downarrow}
\quad
\text{vs.}
\quad
\underbrace{\text{Containment Fidelity}}_{\uparrow}
\quad
\text{under}
\quad
\underbrace{\text{Disruption Budget}}_{\leq B}
$$

---

# Roadmap

```mermaid
timeline
    title ShadowCut Research Roadmap

    Prototype : Dynamic graph state
              : Bounded neighborhood extraction
              : Minimum-cut containment
              : Initial scaling benchmark

    Phase 2 : Adaptive neighborhood radius
            : Local-vs-global fidelity evaluation
            : Larger graph experiments
            : Statistical benchmark methodology

    Phase 3 : Realistic authentication datasets
            : Temporal attack scenarios
            : Multi-target optimization
            : Dynamic/incremental graph algorithms

    Phase 4 : Network enforcement
            : Firewall / NAC integration
            : SDN-based containment
            : Online event processing
```

---

# Citation

If you use ShadowCut in academic work, cite the project as:

```bibtex
@software{shadowcut,
  title  = {ShadowCut: Bounded-Neighborhood Graph-Cut Optimization for Lateral Movement Containment},
  author = {Ajaykrishnan Haridas},
  year   = {2026},
  url    = {https://github.com/apexajay-rc/shadowcut}
}
```

---

<div align="center">

### ShadowCut

**Localize the attack surface.  
Optimize the cut.  
Minimize the disruption.**

</div>
