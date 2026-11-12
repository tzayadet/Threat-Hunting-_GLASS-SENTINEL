# Glass Sentinel · Threat-Hunting Lab

[![Tests](https://github.com/tzayadet/Threat-Hunting-_GLASS-SENTINEL/actions/workflows/tests.yml/badge.svg)](https://github.com/tzayadet/Threat-Hunting-_GLASS-SENTINEL/actions/workflows/tests.yml)

Small Python detection-engineering exercise that correlates authentication failures with unusually large, unapproved data exports.

The project is intentionally self-contained: it reads a CSV event stream, applies a transparent correlation rule and prints alerts. It does not connect to endpoints, collect telemetry, execute commands on remote systems or send data over the network.

## Detection logic

An export is flagged when all of the following conditions match:

1. The event is an `export`.
2. The export is not marked as approved.
3. The exported volume is at least 50 MB by default.
4. A successful login for the same user and source IP occurred within the preceding 10 minutes.
5. At least two failed logins for that same user and IP occurred within the 10 minutes before the successful login.

The thresholds can be changed from the command line. This is a deliberately narrow correlation rule for demonstration, not a complete account-compromise detector.

## Requirements

- Python 3.10+
- No third-party dependencies

## Run

From the repository root:

```bash
python glass_sentinel.py
```

The default input is `data/sample_events.csv`, a synthetic dataset using documentation-only IP ranges.

Use a different CSV:

```bash
python glass_sentinel.py path/to/events.csv
```

Change the thresholds:

```bash
python glass_sentinel.py --minimum-mb 100 --window-minutes 15
```

CSV columns:

| Column | Meaning |
|---|---|
| `ts` | ISO-8601 event timestamp, including timezone where available |
| `user` | Account name |
| `ip` | Source IP address |
| `event` | `login_fail`, `login_success` or `export` |
| `bytes` | Bytes transferred |
| `approved` | Approval state (`yes/no`, `true/false` or `1/0`) |

## Tests

Run the standard-library test suite:

```bash
python -m unittest discover -s tests -v
```

The tests cover positive detection, approved and small exports, user/IP correlation and the time window.

## Limitations

- The rule uses exact user and IP matching; NAT, proxies, VPNs and shared accounts can affect correlation.
- It does not establish malicious intent. A detection is an investigation lead, not proof of exfiltration.
- The sample data is synthetic and uses RFC 5737 documentation address ranges.
- Production use would require source-specific parsing, event integrity, alert deduplication, richer baselines and tuning against false positives.

## Author and scope

Independent defensive-security learning project by [tzayadet](https://github.com/tzayadet). The name is a project codename and does not imply affiliation with any security unit or organization.
