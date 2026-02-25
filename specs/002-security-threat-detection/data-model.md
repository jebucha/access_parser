# Data Model: Security Threat Detection

## Entities

### SecurityThreatProfile
Configuration object containing thresholds and patterns.
- `patterns`: Map of `ThreatType` to compiled regexes (e.g., `{'xss': r'<script.*', ...}`).
- `frequency_threshold`: Max hits/sec (Default: 20).
- `anomaly_threshold`: Multiplier for status code spikes (Default: 5x baseline).
- `size_threshold`: Max bytes for response bodies (Default: 50MB).
- `whitelist_countries`: List of allowed ISO 3166-1 alpha-2 codes.
- `geoip_db_path`: Path to local MaxMind `.mmdb` file.

### LogEntry (Enriched)
The data structure representing a single processed log line.
- `timestamp`: Datetime of request.
- `client_ip`: Remote host IP.
- `request_line`: Raw `%r` string.
- `status_code`: HTTP response status.
- `response_bytes`: Number of bytes sent.
- `user_agent`: User-Agent header string.
- **`security_flags`**: List of `SecurityFlag` objects.
- **`location`**: Geographic metadata (e.g., `{'country': 'US', 'city': 'Austin'}`).

### SecurityFlag
Metadata about a detected threat.
- `label`: Friendly name (e.g., "SQL Injection Attempt").
- `severity`: Enum (INFO, MEDIUM, HIGH, CRITICAL).
- `threat_type`: Category (Injected, Automated, Geographic, Exfiltration).
- `metadata`: Additional context (e.g., matching pattern, actual rate, delta).

### IPActivityTracker
Internal state tracked per IP to identify patterns over time.
- `request_timestamps`: `deque` of timestamps in the current sliding window.
- `last_request_time`: Timestamp of the previous request for delta calculation.
- `recent_status_codes`: `deque` of recent status codes to detect spikes.
- `is_bot_candidate`: Boolean flag for inhuman request speed.

## Validation Rules
- `client_ip`: Must be a valid IPv4 or IPv6 address.
- `status_code`: Must be between 100 and 599.
- `whitelist_countries`: Each entry must be exactly 2 uppercase letters.
