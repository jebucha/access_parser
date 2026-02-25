# CLI Contract: Security Threat Detection

## Command Line Arguments

The `access-parser` tool will be extended with the following security flags:

| Flag | Description | Default |
|------|-------------|---------|
| `--security` | Enable all security threat detection modules. | Disabled |
| `--geoip-db <path>` | Path to MaxMind `.mmdb` file for geographic resolution. | None |
| `--frequency <int>` | Maximum allowed requests per second from a single IP. | 20 |
| `--anomaly-rate <int>` | Multiplier for 40x/50x status code spikes. | 5 |
| `--size-limit <mb>` | Max allowed response body size (in MB) for data exfiltration detection. | 50 |
| `--whitelist <codes>` | Comma-separated list of ISO 3166-1 country codes (e.g., `US,CA`). | All allowed |
| `--json` | Output log entries enriched with security flags in JSON format. | Human-readable |

## Usage Examples

**Analyze a file with security flags and GeoIP:**
```bash
access-parser --security --geoip-db ./GeoLite2-City.mmdb access.log
```

**Output JSON for automated analysis:**
```bash
access-parser --security --json access.log > security_report.json
```

**Custom frequency and whitelist thresholds:**
```bash
access-parser --security --frequency 10 --whitelist US,DE access.log
```
