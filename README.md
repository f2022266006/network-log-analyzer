# Network Log Analyzer

A beginner-friendly defensive cybersecurity tool that reads OpenSSH-style
authentication logs, counts failed login attempts, finds repeated connections,
identifies IP addresses that cross configurable thresholds, and creates short
text and JSON security reports.

## Why This Project Matters

Authentication logs contain evidence of login attempts and network activity.
Security analysts aggregate these events to find behavior that may deserve
investigation, such as many failed passwords or repeated connections from one
source. This project demonstrates networking, threat analysis, regular
expressions, data processing, reporting, testing, and responsible interpretation.

## Features

- Reads a local UTF-8 log file line by line
- Parses failed and successful OpenSSH logins
- Parses generic OpenSSH connection messages
- Validates IPv4 and IPv6 addresses
- Counts failed logins and connections by IP address
- Tracks usernames targeted by failed logins
- Applies configurable detection thresholds
- Produces human-readable text and structured JSON reports
- Includes safe documentation-only IP ranges in the sample data
- Uses only Python's standard library

## Repository Structure

```text
network-log-analyzer/
├── network_log_analyzer.py
├── README.md
├── LICENSE
├── SECURITY.md
├── .gitignore
├── sample_data/
│   └── auth.log
├── reports/
│   └── .gitkeep
├── tests/
│   └── test_network_log_analyzer.py
└── docs/
    ├── PROJECT_PROPOSAL.md
    └── ARCHITECTURE.md
```

## Requirements

- Python 3.8 or newer
- Windows, Linux, or macOS
- No external packages

## Quick Start

Run this command from the project directory:

```bash
python network_log_analyzer.py sample_data/auth.log
```

The sample is intentionally suspicious. Expected terminal summary:

```text
[OK] Parsed 9 security events from auth.log.
[RESULT] Failed login attempts: 3
[RESULT] Suspicious IP addresses: 2
```

Open the generated files:

- `reports/security_report.txt`
- `reports/security_report.json`

The program returns exit code `1` when suspicious activity is found, which is a
normal alert result rather than a crash. Exit code `0` means no threshold was
reached, and `2` means an input error occurred.

## Custom Detection Thresholds

```bash
python network_log_analyzer.py sample_data/auth.log \
  --failed-threshold 5 \
  --connection-threshold 10
```

## Custom Report Locations

```bash
python network_log_analyzer.py sample_data/auth.log \
  --report reports/my_report.txt \
  --json-report reports/my_report.json
```

## Run the Tests

```bash
python -m unittest discover -s tests -v
```

## Detection Logic

An IP address is marked suspicious when either condition is true:

- Failed logins are greater than or equal to `--failed-threshold`
- Connection attempts are greater than or equal to `--connection-threshold`

These are transparent learning rules, not artificial intelligence. An alert
means “investigate this activity,” not “this address is definitely an attacker.”

## Supported Log Examples

```text
Failed password for root from 192.0.2.10 port 50101 ssh2
Failed password for invalid user admin from 192.0.2.10 port 50102 ssh2
Accepted publickey for student from 203.0.113.5 port 50301 ssh2
Connection from 198.51.100.20 port 50201 on 10.0.0.5 port 22
```

Other formats are counted as ignored lines. Real systems may format logs
differently, so production tools require additional parsers and normalization.

## Documentation

- [Project proposal and objectives](docs/PROJECT_PROPOSAL.md)
- [System architecture](docs/ARCHITECTURE.md)
- [Responsible-use policy](SECURITY.md)

## Limitations

- Supports selected OpenSSH-style messages rather than every log format
- Uses thresholds rather than behavioral machine learning
- Does not enrich addresses with external reputation or location data
- Does not automatically block IP addresses
- Processes one local file per run and does not monitor continuously
- Log evidence can be incomplete or manipulated

## Future Improvements

- Add Apache, Nginx, Windows Event Log, and firewall parsers
- Detect password spraying across multiple usernames
- Group events into time windows
- Add CSV export and visual charts
- Build a small dashboard
- Add continuous ingestion and alert notifications

## Suggested GitHub Topics

`python` · `cybersecurity` · `log-analysis` · `network-security` ·
`threat-detection` · `ssh` · `blue-team`
