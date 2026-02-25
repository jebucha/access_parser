# Tasks: Security Threat Detection

**Feature**: Security Threat Detection
**Branch**: `002-security-threat-detection`
**Implementation Strategy**: MVP focused on User Story 1 (Web Injection Attacks), followed by incremental delivery of automated traffic analysis, bot detection, and geographic correlation.

## Phase 1: Setup

- [X] T001 Initialize security module directory structure at `src/access_parser/security/`
- [X] T002 Create `src/access_parser/security/__init__.py` to expose public analyzer interface
- [X] T003 Initialize test directories at `tests/unit/` and `tests/integration/`
- [X] T004 Add `geoip2` to project dependencies (e.g., `requirements.txt` or `pyproject.toml`)

## Phase 2: Foundational

- [X] T005 Create `SecurityFlag` and `SecurityThreatProfile` data models in `src/access_parser/security/analyzer.py`
- [X] T006 Implement base `SecurityAnalyzer` class structure in `src/access_parser/security/analyzer.py`
- [X] T007 [P] Implement shared utility for loading regex patterns in `src/access_parser/security/patterns.py`

## Phase 3: User Story 1 - Detect Web Injection Attacks (Priority: P1)

**Goal**: Identify XSS, SQLi, and Path Traversal patterns in request lines.
**Independent Test**: Process a log file with injected strings and verify `SecurityFlag` counts for each threat type.

- [X] T008 [P] [US1] Create unit tests for injection pattern matching in `tests/unit/test_security_patterns.py` (Must fail initially)
- [X] T009 [US1] Implement `PatternMatcher` with regex for XSS, SQLi, and Traversal in `src/access_parser/security/patterns.py` using Red-Green-Refactor cycle
- [X] T010 [US1] Integrate `PatternMatcher` into `SecurityAnalyzer.analyze_entry()` in `src/access_parser/security/analyzer.py`
- [X] T011 [US1] Verify US1 with integration test using sample malicious logs in `tests/integration/test_full_security_pipeline.py`

## Phase 4: User Story 2 - Identify Automated Scanning & Brute Force (Priority: P2)

**Goal**: Detect high-frequency requests and status code anomalies.
**Independent Test**: Verify flagging of IPs exceeding 20 hits/sec and 404/403 spikes.

- [X] T012 [P] [US2] Create unit tests for frequency tracking and sliding windows in `tests/unit/test_frequency_tracker.py` (Must fail initially)
- [X] T013 [US2] Implement `IPActivityTracker` with `collections.deque` for hit rate tracking in `src/access_parser/security/trackers.py` using Red-Green-Refactor cycle
- [X] T014 [US2] Implement rolling status code baseline and spike detection logic in `src/access_parser/security/trackers.py`
- [X] T015 [US2] Integrate `IPActivityTracker` into `SecurityAnalyzer` in `src/access_parser/security/analyzer.py`
- [X] T016 [US2] Verify US2 with high-frequency mock log sequences in `tests/integration/test_full_security_pipeline.py`

## Phase 5: User Story 3 - Data Exfiltration & Bot Detection (Priority: P3)

**Goal**: Monitor large responses and suspicious User-Agents.
**Independent Test**: Flag requests with >50MB response size or bot-like User-Agents.

- [X] T017 [P] [US3] Add tests for size thresholding and User-Agent validation in `tests/unit/test_security_patterns.py` (Must fail initially)
- [X] T018 [US3] Implement `time_delta` calculation between sequential requests in `src/access_parser/security/trackers.py`
- [X] T018a [US3] Implement historical baseline calculation logic for response sizes in `src/access_parser/security/analyzer.py`
- [X] T019 [US3] Implement baseline-aware response size and User-Agent validation logic in `src/access_parser/security/analyzer.py` using Red-Green-Refactor cycle
- [X] T020 [US3] Verify US3 with exfiltration and bot-agent test cases in `tests/integration/test_full_security_pipeline.py`

## Phase 6: User Story 4 - Geographic Anomaly Detection (Priority: P4)

**Goal**: Identify traffic from non-whitelisted countries using GeoIP.
**Independent Test**: Resolve IPs to countries and flag those outside the configured whitelist.

- [X] T021 [P] [US4] Create unit tests for GeoIP resolution in `tests/unit/test_geo_lookup.py` (Must fail initially)
- [X] T022 [US4] Implement `GeoResolver` wrapper for `geoip2` in `src/access_parser/security/geo.py` using Red-Green-Refactor cycle
- [X] T023 [US4] Implement country whitelist filtering logic in `src/access_parser/security/analyzer.py`
- [X] T024 [US4] Verify US4 with whitelisted and non-whitelisted IP test cases in `tests/integration/test_full_security_pipeline.py`

## Phase 7: Polish & CLI Integration

- [X] T025 Update `src/access_parser/cli.py` to support new security flags and `--json` output
- [X] T026 Implement human-readable security banner formatting for console output in `src/access_parser/cli.py`
- [X] T027 [P] Update `src/access_parser/parser.py` to optionally pass entries through `SecurityAnalyzer`
- [X] T027a Implement buffering and entry-skipping logic for extreme log volumes in `src/access_parser/parser.py`
- [X] T028 Final end-to-end verification against all measurable outcomes (SC-001 to SC-005)

## Dependencies

- **Story 1 (P1)**: Independent (Blocks US2, US3, US4 for full pipeline integration)
- **Story 2 (P2)**: Depends on Phase 2 Foundations
- **Story 3 (P3)**: Depends on Phase 2 Foundations and US2 tracking logic
- **Story 4 (P4)**: Depends on Phase 2 Foundations

## Parallel Execution Examples

- **Within US1**: T008 (Tests) and T009 (Regex Patterns) can start in parallel.
- **Across Stories**: T012 (US2 Tests) and T021 (US4 Tests) can run in parallel once Foundations are set.
- **Polish**: T026 (UI Formatting) can be done in parallel with T027 (Parser integration).
