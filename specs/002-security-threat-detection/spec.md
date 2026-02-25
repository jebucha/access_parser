# Feature Specification: Security Threat Detection

**Feature Branch**: `002-security-threat-detection`  
**Created**: 2026-02-25  
**Status**: Draft  
**Input**: User description: "Pattern-Based URI Inspection: The app must scan the %r (request line) for common injection signatures, such as ../ for directory traversal, <script> tags for XSS, or SELECT/UNION statements for SQL injection. High-Frequency Thresholding: It needs to track the frequency of requests from a single %h (IP address) to flag potential Brute Force or DDoS attempts if hits exceed a specific count per second. Status Code Anomaly Detection: The parser should monitor for a sudden spike in %s (HTTP status) 404 or 403 errors, which often indicates an automated \"directory busting\" tool or a vulnerability scanner probing your file structure. Large Response Body Monitoring: It must flag unusually high values in the %b (bytes sent) field, which can signal data exfiltration or an attacker successfully downloading sensitive configuration files. Timestamp Sequencing: The application needs to calculate the time delta between entries to identify \"inhuman\" request speeds, distinguishing between a natural user and a rapid-fire automated script. User-Agent Validation: If using the combined pattern, it should check the %{User-Agent}i field against a list of known malicious bots or suspicious headers (like curl or python-requests targeting production endpoints). Geographic Correlation: By integrating a GeoIP database, the app should be able to highlight requests coming from geographic regions where your company has no legitimate users or business presence."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Detect Web Injection Attacks (Priority: P1)

As a Security Administrator, I want the parser to automatically flag requests that contain common attack patterns in the URI so that I can quickly identify and respond to attempted XSS, SQLi, and path traversal attacks.

**Why this priority**: Core security requirement to prevent direct application exploitation.

**Independent Test**: Can be tested by processing a log file containing specific malicious strings (`../`, `<script>`, `UNION SELECT`) and verifying that the output flags these entries with a high-severity security warning.

**Acceptance Scenarios**:

1. **Given** a log entry with `%r` containing `../../../etc/passwd`, **When** processed, **Then** it is flagged as "Path Traversal Attempt".
2. **Given** a log entry with `%r` containing `<script>alert(1)</script>`, **When** processed, **Then** it is flagged as "XSS Attempt".
3. **Given** a log entry with `%r` containing `SELECT * FROM users`, **When** processed, **Then** it is flagged as "SQL Injection Attempt".

---

### User Story 2 - Identify Automated Scanning & Brute Force (Priority: P2)

As a Security Administrator, I want to detect high-frequency requests from a single source and spikes in error status codes so that I can identify bots, scrapers, and automated vulnerability scanners.

**Why this priority**: Crucial for mitigating DoS risks and identifying reconnaissance phases of an attack.

**Independent Test**: Can be tested by providing a log sequence with more than 20 requests per second from a single IP or a 500% increase in 404/403 errors over a 10-second window.

**Acceptance Scenarios**:

1. **Given** an IP address appears more than [threshold] times per second, **When** analyzed, **Then** all entries from that IP are flagged as "High Frequency / Potential DoS".
2. **Given** a sudden spike in 404 (Not Found) or 403 (Forbidden) responses from a specific IP, **When** analyzed, **Then** the IP is flagged as "Automated Scanning / Directory Busting".
3. **Given** timestamps between consecutive requests from the same IP are consistently under 100ms, **When** analyzed, **Then** the traffic is flagged as "Inhuman Speed / Automated Script".

---

### User Story 3 - Data Exfiltration & Bot Detection (Priority: P3)

As a Security Administrator, I want to be alerted to unusually large response bodies and suspicious User-Agents so that I can detect potential data leaks or unauthorized tool usage.

**Why this priority**: Helps detect successful exploits where sensitive data is actually being retrieved.

**Independent Test**: Can be tested by processing logs with `%b` values exceeding 100MB and `%{User-Agent}i` strings matching known malicious tools (e.g., `sqlmap`, `nmap`).

**Acceptance Scenarios**:

1. **Given** a response size `%b` that is 3 standard deviations above the historical mean for that resource, **When** processed, **Then** it is flagged as "Large Response / Potential Exfiltration".
2. **Given** a User-Agent string like `python-requests/2.25.1` targeting a sensitive endpoint, **When** processed, **Then** it is flagged as "Suspicious Tooling".

---

### User Story 4 - Geographic Anomaly Detection (Priority: P4)

As a Security Administrator, I want to see the geographic origin of requests so that I can identify traffic from regions where our business does not operate.

**Why this priority**: Provides context for risk assessment and helps identify targeted attacks from unexpected locations.

**Independent Test**: Can be tested by integrating a test GeoIP database and verifying that IPs from "non-legitimate" countries are highlighted in the report.

**Acceptance Scenarios**:

1. **Given** a request from an IP mapped to a country not on the "Business-Approved" list, **When** processed, **Then** the entry is flagged as "Geographic Anomaly".

### Edge Cases

- **Missing Data Fields**: How does the system handle log entries with missing values (e.g., `-` in the `%b` or `%{User-Agent}i` fields)?
- **Local/Internal Traffic**: Should requests from private IP ranges (e.g., `10.0.0.0/8`, `192.168.0.0/16`) be exempted from security frequency flagging?
- **Ambiguous Signatures**: How are overlapping patterns handled (e.g., an entry that matches both "XSS" and "Path Traversal")?
- **Invalid GeoIP Resolution**: What happens when an IP cannot be resolved to a country in the GeoIP database?
- **Extreme Log Volume**: How should the system respond if the rate of incoming log entries exceeds the real-time processing capability? (Assumption: Buffer or skip entries with a warning).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST scan the `%r` field against a configurable list of regex patterns for directory traversal, XSS, and SQL injection.
- **FR-002**: System MUST track request counts per IP (`%h`) within a sliding 1-second window and flag IPs exceeding the configured threshold.
- **FR-003**: System MUST calculate the rolling average of 404 and 403 status codes (`%s`) and flag IPs that exceed 5x the average within a 1-minute window.
- **FR-004**: System MUST flag entries where the `%b` field exceeds a configurable byte-size threshold (Default: 50MB).
- **FR-005**: System MUST calculate the time difference (delta) between consecutive log entries from the same `%h`.
- **FR-006**: System MUST flag requests with `%h` deltas consistently below 100ms as "Automated".
- **FR-007**: System MUST validate `%{User-Agent}i` against a blacklist of known malicious or suspicious bot strings.
- **FR-008**: System MUST integrate with a GeoIP database (e.g., MaxMind MMDB format) to resolve `%h` to a country/region.
- **FR-009**: System MUST allow users to define a whitelist of "Legitimate Business Regions" (ISO 3166-1 alpha-2 country codes) and flag any IP from outside these regions.

### Key Entities *(include if feature involves data)*

- **Security Threat Profile**: A set of criteria (patterns, thresholds, blacklists) used to evaluate a log entry.
- **Flagged Entry**: A log entry that has been enriched with one or more security warning labels.
- **GeoIP Database**: A local database file used for IP-to-location resolution.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: System identifies 100% of the sample injection signatures provided in the configuration.
- **SC-002**: Automated traffic detection flags 99% of requests with sub-100ms intervals from the same IP.
- **SC-003**: GeoIP resolution completes in under 1ms per entry on average.
- **SC-004**: System accurately flags status code spikes within 5 entries of the threshold being reached.
- **SC-005**: False positive rate for "Large Response" flags is under 5% when using baseline-aware thresholds.

## Assumptions

- **A-001**: The log files follow standard CLF or Combined formats where `%r`, `%h`, `%s`, and `%b` are present.
- **A-002**: A GeoIP database file is available locally in a compatible format (e.g., `.mmdb`).
- **A-003**: The "specific count per second" for thresholding defaults to 20 hits/sec unless configured otherwise.
- **A-004**: The system performs passive analysis (offline log parsing) rather than active inline blocking.
