# Implementation Plan: Security Threat Detection

**Branch**: `002-security-threat-detection` | **Date**: 2026-02-25 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/002-security-threat-detection/spec.md`

## Summary

Implement a security enrichment layer for the access log parser that identifies common web attacks (XSS, SQLi, Path Traversal), automated traffic patterns (DDoS, Brute Force, Scanning), and geographic anomalies. The system will use regex-based signature matching, sliding-window frequency analysis, and GeoIP integration to flag suspicious log entries.

## Technical Context

**Language/Version**: Python 3.12  
**Primary Dependencies**: `geoip2` (MaxMind), `argparse`, `re` (Standard Library)  
**Storage**: N/A (Streaming/File-based processing)  
**Testing**: `pytest`  
**Target Platform**: Linux, macOS  
**Project Type**: CLI tool / Library  
**Performance Goals**: >50,000 lines/sec (on standard hardware)  
**Constraints**: <100MB memory footprint, offline-capable (local MMDB)  
**Scale/Scope**: Support for Apache/Nginx Combined log formats

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- [x] **Library-First**: Detection logic will be encapsulated in a `SecurityAnalyzer` class within a library module, independent of the CLI wrapper.
- [x] **CLI Interface**: Functionality will be exposed via CLI flags (e.g., `--security`, `--geoip-db`). Supports both human-readable and JSON output formats.
- [x] **Test-First**: Core regex patterns and frequency window logic will have comprehensive unit tests before implementation.
- [x] **Integration Testing**: Sample log files with injected attack patterns will be used to verify the full pipeline.
- [x] **Simplicity**: Favor standard library (`collections.deque`, `datetime`) over heavy frameworks like `pandas` for rolling metrics to minimize dependency bloat.

## Project Structure

### Documentation (this feature)

```text
specs/002-security-threat-detection/
├── spec.md              # Feature specification
├── plan.md              # Implementation plan (this file)
├── research.md          # Phase 0 findings
├── data-model.md        # Phase 1 design entities
├── quickstart.md        # User onboarding guide
└── contracts/           # CLI and JSON schema definitions
```

### Source Code (repository root)

```text
src/
├── access_parser/
│   ├── __init__.py
│   ├── parser.py        # Core log parser (existing)
│   ├── security/
│   │   ├── __init__.py
│   │   ├── analyzer.py  # SecurityAnalyzer library
│   │   ├── patterns.py  # Regex definitions
│   │   ├── trackers.py  # Frequency and anomaly state
│   │   └── geo.py       # GeoIP integration
│   └── cli.py           # CLI entry point
tests/
├── unit/
│   ├── test_security_patterns.py
│   ├── test_frequency_tracker.py
│   └── test_geo_lookup.py
├── integration/
│   └── test_full_security_pipeline.py
```

**Structure Decision**: Python package structure with a dedicated `security/` submodule. This allows the core parser to remain independent of the security enrichment logic.

## Implementation Phases

### Phase 1: Project Setup & Regex Engine
- **Goal**: Initialize the security module and implement the core signature matcher.
- **Tasks**:
  - Scaffold `src/access_parser/security/` and `tests/`.
  - Implement `PatternMatcher` in `patterns.py` for XSS, SQLi, and Traversal.
  - Add unit tests for diverse malicious URI strings.

### Phase 2: Frequency Analysis & Sliding Window
- **Goal**: Detect high-volume traffic and "inhuman" request speeds.
- **Tasks**:
  - Implement `IPActivityTracker` using `collections.deque`.
  - Add rate-limiting logic (hits/sec).
  - Add time-delta calculation for sequential requests from the same IP.
  - Test with mock timestamp sequences.

### Phase 3: Anomaly Detection (Status Code Spikes)
- **Goal**: Detect spikes in 40x/50x error codes.
- **Tasks**:
  - Implement rolling baseline for status codes in `trackers.py`.
  - Implement spike detection logic (e.g., current error rate > 5x baseline).
  - Test with varying error ratios.

### Phase 4: GeoIP & Geographic Filtering
- **Goal**: Integrate MaxMind resolution and country whitelisting.
- **Tasks**:
  - Add `geoip2` dependency.
  - Implement `GeoResolver` in `geo.py`.
  - Implement `WhitelistFilter` for ISO 3166-1 codes.
  - Test with sample IP addresses.

### Phase 5: CLI Wrapper & Output Formatting
- **Goal**: Expose security features via command line.
- **Tasks**:
  - Update `cli.py` with new security arguments.
  - Implement JSON enrichment for log entries.
  - Implement human-readable security banners in output.

### Phase 6: E2E Integration & Final Docs
- **Goal**: Ensure everything works together under realistic loads.
- **Tasks**:
  - Create integration tests with large sample log files.
  - Verify performance targets (50k+ lines/sec).
  - Update `quickstart.md` and `plan.md` status.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |
