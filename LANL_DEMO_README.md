# ShadowCut LANL Evidence Mode

This bundle adds a **real-data ingestion path** without changing the existing
controlled demo.

## What gets added

```text
src/
├── ingestion/
│   ├── lanl_parser.py       # official LANL auth/red-team parsers
│   └── lanl_snapshot.py     # incident-centered graph builder
├── main_lanl.py             # CLI evidence-mode runner
└── ui/
    └── lanl_dashboard.py    # separate Streamlit evidence console

tests/
├── fixtures/lanl/
│   ├── auth_sample.txt
│   └── redteam_sample.txt
└── test_lanl_ingestion.py
```

## Integration philosophy

The existing prototype remains unchanged.

```text
LANL auth.txt.gz
        ↓
lanl_parser.py
        ↓
EnterpriseGraph           ← existing graph abstraction
        ↓
ShadowCutController       ← existing containment controller
        ↓
global verification
```

The parser is streaming and supports `.txt` and `.gz`.

The graph semantics are:

```text
source computer  →  destination computer
```

Repeated observations increment `observations`; they do **not** silently become
higher disruption cost.

For a LANL red-team event, the demo interpretation is:

```text
red-team source computer      → attacker
red-team destination computer → protected target for this scenario
```

LANL provides ground-truth compromise events, but it does not provide a business
criticality label for the destination. Therefore the dashboard deliberately calls
it a **destination/target**, not a universally "critical asset".

## Install

From repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-lanl.txt
```

## Verify the adapter before touching real data

```bash
PYTHONPATH=./src pytest -q
```

The included fixture is shaped like the official LANL formats.

## Put the real LANL files locally

Download the official **Comprehensive, Multi-Source Cyber-Security Events**
dataset from the LANL Cyber Security Research data page.

Expected files:

```text
data/lanl/
├── auth.txt.gz
└── redteam.txt.gz
```

Do not commit these datasets to GitHub.

The full auth file is multi-gigabyte compressed, so the loader intentionally reads
only an incident-centered time window and caps the number of events.

## Run the CLI

```bash
PYTHONPATH=./src python3 src/main_lanl.py \
  --auth data/lanl/auth.txt.gz \
  --redteam data/lanl/redteam.txt.gz \
  --incident-index 0 \
  --max-events 100000 \
  --budget 10 \
  --initial-k 2 \
  --max-k 5
```

## Run the LANL evidence console

```bash
PYTHONPATH=./src streamlit run src/ui/lanl_dashboard.py
```

Default paths in the sidebar:

```text
data/lanl/auth.txt.gz
data/lanl/redteam.txt.gz
```

Workflow:

```text
Load LANL Snapshot
        ↓
inspect incident + graph statistics
        ↓
Run ShadowCut
        ↓
localized optimization
        ↓
selected containment edges
        ↓
apply to graph copy
        ↓
independent global reachability verification
```

The visualization shows a small incident-centered neighborhood so that thousands
of LANL nodes do not overwhelm the browser. ShadowCut itself runs on the full
ingested graph snapshot.

## Tomorrow's demo positioning

Use this as **Evidence Mode**, not as the only live demo.

Recommended sequence:

1. Run the existing controlled demo first. It has deterministic attack animation.
2. Switch to LANL Evidence Console.
3. Explain that the graph source has changed from a synthetic controlled network to
   anonymized enterprise authentication telemetry.
4. Show the LANL red-team event used as ground truth.
5. Run ShadowCut on the real-data graph snapshot.
6. Show the selected cut and global containment verification.

Do not claim that LANL provides "critical asset" labels or that the prototype has
performed live firewall enforcement. This mode demonstrates real telemetry ingestion
and graph-based containment analysis.
