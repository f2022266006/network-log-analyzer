# Project Proposal

## Project Title

**Network Log Analyzer: Threshold-Based Authentication Threat Detection**

## Problem Statement

Network and authentication logs can contain thousands of records, making manual
review slow and inconsistent. Beginners need a transparent defensive tool that
turns raw OpenSSH-style messages into useful counts and highlights repeated
failed logins or connection attempts for further investigation.

## Aim

To build a Python command-line application that parses authentication logs,
summarizes network activity, applies explainable detection thresholds, and
generates a concise security report.

## Objectives

1. Read a user-selected authentication log safely and efficiently.
2. Parse failed logins, successful logins, and connection messages.
3. Extract and validate source IP addresses, ports, and usernames.
4. Count failed login attempts for each source IP address.
5. Count repeated connection attempts for each source IP address.
6. Identify IP addresses that reach configurable alert thresholds.
7. Record the usernames targeted by failed login attempts.
8. Generate both human-readable and machine-readable security reports.
9. Test parsing, aggregation, thresholds, and invalid-data handling.
10. Document the limitations and responsible interpretation of alerts.

## Scope

### Included

- Selected OpenSSH-style authentication and connection messages
- IPv4 and IPv6 validation
- Per-IP aggregation
- Configurable failed-login and connection thresholds
- Text and JSON reports
- Safe sample logs using documentation-only IP ranges

### Excluded

- Automatic blocking or active response
- Live packet capture
- External IP reputation lookup
- Continuous real-time monitoring
- Attribution of activity to a person
- A claim that threshold alerts prove malicious intent

## Methodology

1. Define supported log patterns and a normalized event model.
2. Parse messages using documented regular expressions.
3. Validate extracted addresses using Python's `ipaddress` module.
4. Aggregate events using counters and sets.
5. Apply configurable and explainable threshold rules.
6. Produce text and JSON output for human and programmatic use.
7. Validate the system with automated and end-to-end tests.

## Functional Requirements

| ID | Requirement |
| --- | --- |
| FR-01 | Read a local UTF-8 authentication log. |
| FR-02 | Parse supported failed, successful, and connection messages. |
| FR-03 | Count activity by valid source IP address. |
| FR-04 | Identify IPs reaching either configured threshold. |
| FR-05 | Explain why each IP was marked suspicious. |
| FR-06 | Write text and JSON reports. |

## Non-Functional Requirements

- **Clarity:** Detection rules and reasons must be explainable.
- **Privacy:** No data is transmitted to external services.
- **Portability:** Only the Python standard library is required.
- **Maintainability:** Parsing, analysis, and reporting are separate functions.
- **Safety:** The project analyzes logs and performs no blocking or exploitation.

## Tools and Technologies

- Python 3.8+
- Regular expressions (`re`)
- IP validation (`ipaddress`)
- Counters and dictionaries (`collections`)
- JSON processing (`json`)
- Automated testing (`unittest`)
- Git and GitHub

## Expected Outcomes

- Correct event extraction from supported log messages
- Reliable counts of failed logins and connections
- Explainable suspicious-IP findings
- Short text and detailed JSON reports
- A defensible blue-team cybersecurity portfolio project

## Evaluation Criteria

- All unit tests pass.
- Invalid IP addresses are ignored.
- Unrecognized lines do not stop analysis.
- Threshold rules detect the intended sample behavior.
- Text and JSON reports are generated successfully.
- Report totals match the parsed events.

## Future Work

Future versions can add multiple log sources, time-window rules, visualization,
continuous monitoring, external enrichment, and carefully evaluated anomaly
detection.
