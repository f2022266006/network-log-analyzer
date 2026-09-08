#!/usr/bin/env python3
"""Analyze OpenSSH-style logs and generate a small defensive security report."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional


FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from "
    r"(?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
CONNECTION_RE = re.compile(
    r"Connection from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)


@dataclass(frozen=True)
class LogEvent:
    line_number: int
    event_type: str
    ip_address: str
    username: Optional[str] = None
    port: Optional[int] = None


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_line(line: str, line_number: int) -> Optional[LogEvent]:
    """Convert one supported log line into a normalized security event."""
    for pattern, event_type in (
        (FAILED_RE, "failed_login"),
        (ACCEPTED_RE, "successful_login"),
        (CONNECTION_RE, "connection"),
    ):
        match = pattern.search(line)
        if match and valid_ip(match.group("ip")):
            fields = match.groupdict()
            return LogEvent(
                line_number=line_number,
                event_type=event_type,
                ip_address=fields["ip"],
                username=fields.get("user"),
                port=int(fields["port"]),
            )
    return None


def read_events(log_path: Path) -> tuple[List[LogEvent], int]:
    """Read a UTF-8 log file, returning parsed events and ignored-line count."""
    events: List[LogEvent] = []
    ignored = 0
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, start=1):
                event = parse_line(line, line_number)
                if event:
                    events.append(event)
                else:
                    ignored += 1
    except OSError as error:
        raise ValueError(f"Could not read log file: {error}") from error
    return events, ignored


def analyze_events(
    events: Iterable[LogEvent], failed_threshold: int, connection_threshold: int
) -> dict:
    """Aggregate events and apply transparent threshold-based detection rules."""
    events = list(events)
    failed = Counter()
    connections = Counter()
    successful = Counter()
    targeted_users = defaultdict(set)

    for event in events:
        if event.event_type == "failed_login":
            failed[event.ip_address] += 1
            connections[event.ip_address] += 1
            if event.username:
                targeted_users[event.ip_address].add(event.username)
        elif event.event_type == "successful_login":
            successful[event.ip_address] += 1
            connections[event.ip_address] += 1
        elif event.event_type == "connection":
            connections[event.ip_address] += 1

    suspicious = []
    for ip_address in sorted(set(failed) | set(connections)):
        reasons = []
        if failed[ip_address] >= failed_threshold:
            reasons.append(
                f"failed logins ({failed[ip_address]}) reached threshold "
                f"({failed_threshold})"
            )
        if connections[ip_address] >= connection_threshold:
            reasons.append(
                f"connection attempts ({connections[ip_address]}) reached threshold "
                f"({connection_threshold})"
            )
        if reasons:
            suspicious.append(
                {
                    "ip_address": ip_address,
                    "failed_logins": failed[ip_address],
                    "connection_attempts": connections[ip_address],
                    "targeted_usernames": sorted(targeted_users[ip_address]),
                    "reasons": reasons,
                }
            )

    return {
        "total_parsed_events": len(events),
        "failed_login_attempts": sum(failed.values()),
        "successful_logins": sum(successful.values()),
        "connection_attempts": sum(connections.values()),
        "unique_ip_addresses": len(connections),
        "failed_logins_by_ip": dict(sorted(failed.items())),
        "connections_by_ip": dict(sorted(connections.items())),
        "suspicious_ip_addresses": suspicious,
        "thresholds": {
            "failed_logins": failed_threshold,
            "connection_attempts": connection_threshold,
        },
    }


def create_text_report(analysis: dict, source: Path, ignored_lines: int) -> str:
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines = [
        "NETWORK LOG SECURITY REPORT",
        "=" * 31,
        f"Generated (UTC): {generated}",
        f"Source log: {source}",
        "",
        "SUMMARY",
        "-------",
        f"Parsed security events: {analysis['total_parsed_events']}",
        f"Ignored/unrecognized lines: {ignored_lines}",
        f"Failed login attempts: {analysis['failed_login_attempts']}",
        f"Successful logins: {analysis['successful_logins']}",
        f"Connection attempts: {analysis['connection_attempts']}",
        f"Unique IP addresses: {analysis['unique_ip_addresses']}",
        f"Suspicious IP addresses: {len(analysis['suspicious_ip_addresses'])}",
        "",
        "SUSPICIOUS IP DETAILS",
        "---------------------",
    ]
    if not analysis["suspicious_ip_addresses"]:
        lines.append("No IP address reached the configured thresholds.")
    else:
        for item in analysis["suspicious_ip_addresses"]:
            users = ", ".join(item["targeted_usernames"]) or "None recorded"
            lines.extend(
                [
                    f"IP: {item['ip_address']}",
                    f"  Failed logins: {item['failed_logins']}",
                    f"  Connection attempts: {item['connection_attempts']}",
                    f"  Targeted usernames: {users}",
                    f"  Detection reasons: {'; '.join(item['reasons'])}",
                ]
            )
    lines.extend(
        [
            "",
            "ANALYST NOTE",
            "------------",
            "Threshold alerts indicate behavior worth investigating; they do not",
            "prove that an IP address or user is malicious. Correlate findings with",
            "other authorized security evidence before taking action.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_reports(
    analysis: dict,
    events: List[LogEvent],
    source: Path,
    ignored_lines: int,
    text_path: Path,
    json_path: Path,
) -> None:
    text_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    text_path.write_text(
        create_text_report(analysis, source, ignored_lines), encoding="utf-8"
    )
    json_payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_log": str(source),
        "ignored_lines": ignored_lines,
        "analysis": analysis,
        "parsed_events": [asdict(event) for event in events],
    }
    json_path.write_text(json.dumps(json_payload, indent=2), encoding="utf-8")


def positive_integer(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("threshold must be at least 1")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze OpenSSH-style authentication logs for suspicious activity."
    )
    parser.add_argument("log_file", type=Path, help="Log file to analyze")
    parser.add_argument("--failed-threshold", type=positive_integer, default=3)
    parser.add_argument("--connection-threshold", type=positive_integer, default=5)
    parser.add_argument("--report", type=Path, default=Path("reports/security_report.txt"))
    parser.add_argument(
        "--json-report", type=Path, default=Path("reports/security_report.json")
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        source = args.log_file.expanduser().resolve()
        events, ignored = read_events(source)
        analysis = analyze_events(
            events, args.failed_threshold, args.connection_threshold
        )
        write_reports(
            analysis, events, source, ignored, args.report, args.json_report
        )
    except ValueError as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 2

    suspicious_count = len(analysis["suspicious_ip_addresses"])
    print(f"[OK] Parsed {len(events)} security events from {source.name}.")
    print(f"[RESULT] Failed login attempts: {analysis['failed_login_attempts']}")
    print(f"[RESULT] Suspicious IP addresses: {suspicious_count}")
    print(f"[REPORT] {args.report.resolve()}")
    return 1 if suspicious_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
