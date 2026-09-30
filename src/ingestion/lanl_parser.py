"""
LANL authentication/red-team data adapters.

This module converts the official LANL text formats into:
1. normalized Python dataclasses, and
2. the existing ShadowCut EnterpriseGraph abstraction.

The parser is streaming: it never loads the multi-gigabyte auth file into memory.
"""

from __future__ import annotations

import gzip
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterator, Optional, TextIO, Union

from graph.graph_state import EnterpriseGraph


PathLike = Union[str, Path]


@dataclass(frozen=True, slots=True)
class LANLAuthEvent:
    timestamp: float
    source_user: str
    destination_user: str
    source_computer: str
    destination_computer: str
    authentication_type: str
    logon_type: str
    authentication_orientation: str
    status: str


@dataclass(frozen=True, slots=True)
class LANLRedTeamEvent:
    timestamp: float
    user: str
    source_computer: str
    destination_computer: str


@dataclass(frozen=True, slots=True)
class LANLSnapshotStats:
    events_read: int
    events_used: int
    events_skipped: int
    nodes: int
    edges: int
    start_time: Optional[float]
    end_time: Optional[float]


def _open_text(path: PathLike) -> TextIO:
    """Open plain-text or .gz input using UTF-8 text decoding."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"LANL data file not found: {path}")

    if path.suffix == ".gz":
        return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
    return open(path, mode="rt", encoding="utf-8", errors="replace")


def _clean(value: str) -> str:
    return value.strip()


def parse_auth_line(line: str) -> LANLAuthEvent:
    fields = [_clean(part) for part in line.rstrip("\n\r").split(",")]
    if len(fields) != 9:
        raise ValueError(
            f"Expected 9 LANL auth fields, received {len(fields)}: {line[:160]!r}"
        )

    return LANLAuthEvent(
        timestamp=float(fields[0]),
        source_user=fields[1],
        destination_user=fields[2],
        source_computer=fields[3],
        destination_computer=fields[4],
        authentication_type=fields[5],
        logon_type=fields[6],
        authentication_orientation=fields[7],
        status=fields[8],
    )


def parse_redteam_line(line: str) -> LANLRedTeamEvent:
    fields = [_clean(part) for part in line.rstrip("\n\r").split(",")]
    if len(fields) != 4:
        raise ValueError(
            f"Expected 4 LANL red-team fields, received {len(fields)}: {line[:160]!r}"
        )

    return LANLRedTeamEvent(
        timestamp=float(fields[0]),
        user=fields[1],
        source_computer=fields[2],
        destination_computer=fields[3],
    )


def iter_auth_events(
    path: PathLike,
    *,
    success_only: bool = True,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    max_events: Optional[int] = None,
) -> Iterator[LANLAuthEvent]:
    """
    Stream LANL auth events.

    Events outside [start_time, end_time] are ignored. max_events limits
    accepted events, not raw lines scanned.
    """
    accepted = 0
    with _open_text(path) as handle:
        for line_number, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue

            try:
                event = parse_auth_line(raw)
            except ValueError:
                # Keep the ingest path alive when an individual line is malformed.
                continue

            if start_time is not None and event.timestamp < start_time:
                continue
            if end_time is not None and event.timestamp > end_time:
                # LANL auth data is time ordered in the released dataset.
                # We can stop early once we move beyond the requested window.
                return

            if success_only and event.status.lower() != "success":
                continue

            yield event
            accepted += 1

            if max_events is not None and accepted >= max_events:
                return


def iter_redteam_events(
    path: PathLike,
    *,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    max_events: Optional[int] = None,
) -> Iterator[LANLRedTeamEvent]:
    """Stream LANL red-team compromise events."""
    accepted = 0
    with _open_text(path) as handle:
        for raw in handle:
            if not raw.strip():
                continue

            try:
                event = parse_redteam_line(raw)
            except ValueError:
                continue

            if start_time is not None and event.timestamp < start_time:
                continue
            if end_time is not None and event.timestamp > end_time:
                continue

            yield event
            accepted += 1

            if max_events is not None and accepted >= max_events:
                return


def load_redteam_events(path: PathLike) -> list[LANLRedTeamEvent]:
    """Load the small LANL red-team ground-truth file."""
    return list(iter_redteam_events(path))


def build_auth_graph(
    path: PathLike,
    graph_system: EnterpriseGraph,
    *,
    success_only: bool = True,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    max_events: Optional[int] = 100_000,
    disruption_cost: float = 1.0,
) -> LANLSnapshotStats:
    """
    Stream auth events into the existing EnterpriseGraph.

    Graph semantics:
        source computer -> destination computer

    Authentication frequency is stored by EnterpriseGraph as observations;
    it is intentionally NOT converted into disruption cost.
    """
    events_read = 0
    events_used = 0
    events_skipped = 0

    actual_start: Optional[float] = None
    actual_end: Optional[float] = None

    path_obj = Path(path)
    with _open_text(path_obj) as handle:
        for raw in handle:
            if not raw.strip():
                continue

            events_read += 1

            try:
                event = parse_auth_line(raw)
            except ValueError:
                events_skipped += 1
                continue

            if start_time is not None and event.timestamp < start_time:
                continue

            if end_time is not None and event.timestamp > end_time:
                # Official LANL auth data is time ordered.
                break

            if success_only and event.status.lower() != "success":
                continue

            graph_system.ingest_auth_event(
                source=event.source_computer,
                target=event.destination_computer,
                timestamp=event.timestamp,
                disruption_cost=disruption_cost,
            )

            events_used += 1
            actual_start = event.timestamp if actual_start is None else min(actual_start, event.timestamp)
            actual_end = event.timestamp if actual_end is None else max(actual_end, event.timestamp)

            if max_events is not None and events_used >= max_events:
                break

    return LANLSnapshotStats(
        events_read=events_read,
        events_used=events_used,
        events_skipped=events_skipped,
        nodes=graph_system.G.number_of_nodes(),
        edges=graph_system.G.number_of_edges(),
        start_time=actual_start,
        end_time=actual_end,
    )
