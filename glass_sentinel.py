#!/usr/bin/env python3
"""Glass Sentinel: correlate failed logins with unapproved large exports."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    user: str
    ip: str
    event: str
    bytes_transferred: int
    approved: bool


@dataclass(frozen=True)
class Alert:
    user: str
    ip: str
    timestamp: datetime
    bytes_transferred: int
    failed_logins: int


def load_events(csv_path: Path) -> list[Event]:
    """Load and validate events from a CSV file."""
    events: list[Event] = []
    with csv_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"ts", "user", "ip", "event", "bytes", "approved"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            missing = sorted(required - set(reader.fieldnames or []))
            raise ValueError(f"Missing CSV columns: {', '.join(missing)}")

        for line_number, row in enumerate(reader, start=2):
            try:
                events.append(
                    Event(
                        timestamp=datetime.fromisoformat(row["ts"]),
                        user=row["user"].strip(),
                        ip=row["ip"].strip(),
                        event=row["event"].strip().lower(),
                        bytes_transferred=int(row["bytes"]),
                        approved=row["approved"].strip().lower() in {"yes", "true", "1"},
                    )
                )
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid event on CSV line {line_number}: {exc}") from exc

    return sorted(events, key=lambda item: item.timestamp)


def detect_suspicious_exports(
    events: Iterable[Event],
    *,
    minimum_bytes: int = 50_000_000,
    window: timedelta = timedelta(minutes=10),
    minimum_failed_logins: int = 2,
) -> list[Alert]:
    """Flag large, unapproved exports preceded by failed logins and a success."""
    ordered = sorted(events, key=lambda item: item.timestamp)
    alerts: list[Alert] = []

    for export in ordered:
        if (
            export.event != "export"
            or export.approved
            or export.bytes_transferred < minimum_bytes
        ):
            continue

        matching_logins = [
            event
            for event in ordered
            if event.user == export.user
            and event.ip == export.ip
            and event.event == "login_success"
            and timedelta(0) <= export.timestamp - event.timestamp <= window
        ]

        for login in matching_logins:
            failed_logins = [
                event
                for event in ordered
                if event.user == login.user
                and event.ip == login.ip
                and event.event == "login_fail"
                and timedelta(0) < login.timestamp - event.timestamp <= window
            ]

            if len(failed_logins) >= minimum_failed_logins:
                alerts.append(
                    Alert(
                        user=export.user,
                        ip=export.ip,
                        timestamp=export.timestamp,
                        bytes_transferred=export.bytes_transferred,
                        failed_logins=len(failed_logins),
                    )
                )
                break

    return alerts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect unapproved large exports correlated with failed logins."
    )
    parser.add_argument(
        "csv_file",
        nargs="?",
        type=Path,
        default=Path(__file__).parent / "data" / "sample_events.csv",
        help="Path to an event CSV (default: bundled synthetic sample).",
    )
    parser.add_argument(
        "--minimum-mb",
        type=float,
        default=50,
        help="Minimum export size in decimal MB (default: 50).",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=10,
        help="Correlation window in minutes (default: 10).",
    )
    args = parser.parse_args()

    if args.minimum_mb <= 0 or args.window_minutes <= 0:
        parser.error("--minimum-mb and --window-minutes must be greater than zero")

    try:
        events = load_events(args.csv_file)
        alerts = detect_suspicious_exports(
            events,
            minimum_bytes=int(args.minimum_mb * 1_000_000),
            window=timedelta(minutes=args.window_minutes),
        )
    except (OSError, ValueError) as exc:
        parser.exit(2, f"glass-sentinel: error: {exc}\n")

    if not alerts:
        print("No suspicious exports detected.")
        return 0

    print(f"Suspicious exports detected: {len(alerts)}")
    for alert in alerts:
        print(
            f"[ALERT] {alert.timestamp.isoformat()} | user={alert.user} "
            f"| ip={alert.ip} | export={alert.bytes_transferred:,} bytes "
            f"| preceding_failed_logins={alert.failed_logins}"
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
