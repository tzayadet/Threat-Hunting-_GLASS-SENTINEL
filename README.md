<p align="center">
  <img src="https://img.shields.io/badge/THREAT_HUNTING-GLASS_SENTINEL-101010?style=for-the-badge&labelColor=050805&color=00FF41" alt="Glass Sentinel"/>
  <img src="https://img.shields.io/badge/PYTHON-LOG_CORRELATION-101010?style=for-the-badge&logo=python&logoColor=00FF41" alt="Python"/>
</p>

# Glass Sentinel | Threat Hunting Lab

A Python detection exercise that correlates authentication failures with large, unapproved data exports. The engine processes local CSV events; the browser showcase uses synthetic data.

<p align="center">
  <a href="https://tzayadet.github.io/Threat-Hunting-_GLASS-SENTINEL/"><strong>PROJECT SHOWCASE ↗</strong></a> ·
  <a href="https://github.com/tzayadet/Threat-Hunting-_GLASS-SENTINEL"><strong>SOURCE CODE</strong></a>
</p>

[![Tests](https://github.com/tzayadet/Threat-Hunting-_GLASS-SENTINEL/actions/workflows/tests.yml/badge.svg)](https://github.com/tzayadet/Threat-Hunting-_GLASS-SENTINEL/actions/workflows/tests.yml)

## Detection logic

An alert is generated when all of the following conditions match:

1. The event is a data export.
2. The export is not marked as approved.
3. The exported volume reaches the configured threshold (50 MB by default).
4. The same user and source IP recorded a successful login within the previous 10 minutes.
5. At least two failed authentication attempts for that user and IP occurred before the successful login within the configured window.

Thresholds can be changed through command-line options.

## Requirements and usage

Python 3.10+. No external dependencies are required.

```bash
python glass_sentinel.py
python glass_sentinel.py path/to/events.csv
python glass_sentinel.py --minimum-mb 100 --window-minutes 15
```

The default dataset is `data/sample_events.csv` and uses documentation IP ranges reserved by RFC 5737.

## Input format

| Field | Description |
|---|---|
| `ts` | ISO 8601 timestamp |
| `user` | Account associated with the event |
| `ip` | Source IP address |
| `event` | `login_fail`, `login_success` or `export` |
| `bytes` | Transferred volume in bytes |
| `approved` | Approval status |

## Tests

```bash
python -m unittest discover -s tests -v
```

## Showcase and deployment

The [static showcase](https://tzayadet.github.io/Threat-Hunting-_GLASS-SENTINEL/) uses synthetic events. It does not connect to endpoints, collect telemetry or transmit data. The source page is available in [docs/index.html](docs/index.html).

Pages deployment is defined in `.github/workflows/`. If the first deployment has not completed, enable GitHub Pages with GitHub Actions and follow the workflow's repository-variable requirements.

## Scope and limitations

Correlation uses exact user and IP matching. NAT, VPNs, proxies and shared accounts can affect the result. An alert is an investigation lead, not proof of exfiltration or malicious activity.

A production implementation would require source-specific parsers, integrity controls, alert deduplication and threshold tuning against representative data.

## License

See [LICENSE](LICENSE).
