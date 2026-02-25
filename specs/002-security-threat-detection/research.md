# Phase 0: Research & Decisions

## Decision 1: GeoIP Integration
**Decision**: Use `geoip2` for MaxMind MMDB resolution.
**Rationale**: It is the industry standard for IP-to-location resolution. The library is mature, well-documented, and supports local `.mmdb` files, which aligns with the "offline-capable" constraint.
**Alternatives considered**: 
- `ip-api.com` (requires internet access, violates privacy/offline goals)
- `pygeoip` (deprecated)

## Decision 2: High-Frequency Frequency Tracking
**Decision**: Use `collections.deque` for each IP to store request timestamps.
**Rationale**: `deque` provides $O(1)$ operations for adding to the right and popping from the left. By checking the difference between the newest and oldest timestamp in the window, we can easily calculate the current rate without a heavy dependency like `pandas`.
**Alternatives considered**:
- `pandas` (too heavy for a lightweight CLI)
- Simple counters with expiration (harder to handle precise 1-second sliding windows)

## Decision 3: Status Code Anomaly Detection
**Decision**: Maintain a rolling window of recent status codes using `collections.deque(maxlen=100)`.
**Rationale**: We need to track the "normal" rate of 404/403 errors. A fixed-size deque allows us to calculate a baseline error rate for the entire system or per-IP, and then flag sudden deviations (e.g., >5x the current baseline).
**Alternatives considered**:
- External state storage like Redis (not suitable for a standalone CLI tool)

## Decision 4: Web Attack Signature Matching
**Decision**: Centralized dictionary of compiled regex patterns.
**Rationale**: Pre-compiling regex patterns improves performance during high-volume log parsing. Patterns will be categorized by threat type (e.g., `traversal`, `xss`, `sqli`).
**Alternatives considered**:
- Third-party WAF rule parsers (too complex for this tool's scope)

## Decision 5: "Inhuman" Speed Thresholds
**Decision**: Calculate `time_delta` between sequential requests from the same IP.
**Rationale**: Most human interactions involve some "think time." A request sequence with multiple sub-100ms intervals is highly indicative of automated tools (bots, scrapers).
**Alternatives considered**:
- Averaging across long windows (less sensitive to rapid bursts)
