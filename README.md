# Access Log Parser with Security Threat Detection

A high-performance, CLI-based access log parser written in Python. This tool enriches standard Apache/Nginx combined logs with security insights, identifying web attacks, automated traffic patterns, and geographic anomalies.

## Features

- **Pattern-Based URI Inspection**: Detects common injection signatures like Path Traversal (`../`), XSS (`<script>`), and SQL Injection (`UNION SELECT`).
- **High-Frequency Thresholding**: Tracks request frequency per IP using sliding windows to flag potential DDoS or Brute Force attempts.
- **Status Code Anomaly Detection**: Monitors for sudden spikes in 404 or 403 errors, indicating automated scanning or directory busting.
- **Large Response Body Monitoring**: Flags unusually high values in the `%b` field to signal potential data exfiltration.
- **Timestamp Sequencing**: Calculates time deltas between entries to identify "inhuman" request speeds from rapid-fire automated scripts.
- **User-Agent Validation**: Checks for known malicious bots or suspicious headers (e.g., `sqlmap`, `python-requests`).
- **Geographic Correlation**: Integrates MaxMind GeoIP2 to highlight requests from non-whitelisted countries.

## Installation

### Prerequisites

- Python 3.12+
- A MaxMind GeoIP2 database (e.g., `GeoLite2-City.mmdb`) for geographic resolution.

### Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd access_parser
   ```

2. **Create a virtual environment and install dependencies**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install geoip2 pytest
   ```

## Usage

### Basic Parsing

```bash
PYTHONPATH=src python3 -m access_parser.cli access.log
```

### Security Analysis

Enable security threat detection with the `--security` flag. For geographic resolution, provide the path to your MaxMind database:

```bash
PYTHONPATH=src python3 -m access_parser.cli --security --geoip-db ./GeoLite2-City.mmdb access.log
```

### Configuration Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--security` | Enable all security threat detection modules. | Disabled |
| `--geoip-db <path>` | Path to MaxMind `.mmdb` file for geographic resolution. | None |
| `--frequency <int>` | Max allowed requests per second from a single IP. | 20 |
| `--anomaly-rate <int>` | Multiplier for 40x/50x status code spikes. | 5 |
| `--size-limit <mb>` | Max allowed response body size (in MB). | 50 |
| `--whitelist <codes>` | Comma-separated ISO country codes (e.g. `US,CA`). | All allowed |
| `--json` | Output enriched entries in JSON format. | Human-readable |

### Output Examples

**Human-Readable**:
```text
[SECURITY] [HIGH] SQL Injection Attempt from 1.2.3.4 | URI: /index.php?id=1' OR '1'='1'
[SECURITY] [MEDIUM] Automated Scanning / Directory Busting from 5.6.7.8
[SECURITY] [LOW] Geographic Anomaly (Traffic from RU) from 9.10.11.12
```

**JSON**:
```json
{
  "client_ip": "1.2.3.4",
  "timestamp": "25/Feb/2026:12:00:00",
  "request_line": "GET /../../etc/passwd HTTP/1.1",
  "status_code": "403",
  "response_bytes": "1024",
  "security_flags": [
    {
      "label": "Path Traversal Attempt",
      "severity": "HIGH",
      "type": "Injected"
    }
  ]
}
```

## Development

### Running Tests

The project follows a strict TDD approach with comprehensive unit and integration tests.

```bash
PYTHONPATH=. venv/bin/pytest tests/unit/ tests/integration/
```

### Project Structure

- `src/access_parser/security/`: Core security enrichment library.
- `src/access_parser/parser.py`: Log parsing logic.
- `src/access_parser/cli.py`: Command-line interface.
- `specs/002-security-threat-detection/`: Feature specification and implementation plan.
