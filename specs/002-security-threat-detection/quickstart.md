# Quickstart: Security Threat Detection

## Prerequisites
- MaxMind GeoLite2-City (or equivalent) `.mmdb` file for geographic resolution.
- Python 3.12+ installed.
- Log files in standard Apache or Nginx `combined` format.

## Installation
The `access-parser` tool will include a `SecurityAnalyzer` module. Install dependencies with:
```bash
pip install geoip2
```

## Running Your First Analysis

1.  **Download a GeoIP Database**: Obtain `GeoLite2-City.mmdb` from MaxMind.
2.  **Run the parser with security flags**:
    ```bash
    access-parser --security --geoip-db ./GeoLite2-City.mmdb access.log
    ```

3.  **Inspect the output**: Look for `[SECURITY]` labels in the logs, such as:
    ```text
    [SECURITY] HIGH: SQL Injection Attempt from 1.2.3.4 (DE) | URI: /index.php?id=1' OR '1'='1'
    [SECURITY] MEDIUM: Automated Traffic (35 req/sec) from 5.6.7.8 (CN)
    [SECURITY] LOW: Geographic Anomaly (Traffic from RU) from 9.10.11.12
    ```

## Integrating with Monitoring Systems
Use the `--json` flag to stream security events to an ELK stack or Splunk instance:
```bash
access-parser --security --json access.log | curl -X POST -H "Content-Type: application/json" -d @- https://my-logging-endpoint.com/
```
