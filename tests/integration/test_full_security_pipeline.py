import pytest
from src.access_parser.security.analyzer import SecurityAnalyzer
from src.access_parser.security.models import SecurityThreatProfile, ThreatType, Severity

def test_security_analyzer_automated_traffic():
    profile = SecurityThreatProfile(frequency_threshold=5, anomaly_threshold=2)
    analyzer = SecurityAnalyzer(profile)
    ip = "5.6.7.8"
    
    # 5 requests in same second
    for i in range(5):
        entry = {
            "request_line": "GET / HTTP/1.1",
            "client_ip": ip,
            "timestamp": "25/Feb/2026:12:00:00",
            "status_code": "200"
        }
        flags = analyzer.analyze_entry(entry)
        if i == 0:
            assert len(flags) == 0
        else:
            assert any(f.label == "Inhuman Speed / Automated Script" for f in flags)
        
    entry_hf = {
        "request_line": "GET / HTTP/1.1",
        "client_ip": ip,
        "timestamp": "25/Feb/2026:12:00:00",
        "status_code": "200"
    }
    flags_hf = analyzer.analyze_entry(entry_hf)
    assert any(f.label == "High Frequency / Potential DoS" for f in flags_hf)

def test_security_analyzer_status_spike():
    profile = SecurityThreatProfile(anomaly_threshold=2)
    analyzer = SecurityAnalyzer(profile)
    ip = "9.10.11.12"
    
    for _ in range(100):
        entry = {
            "request_line": "GET / HTTP/1.1",
            "client_ip": ip,
            "timestamp": "25/Feb/2026:12:00:00",
            "status_code": "200"
        }
        analyzer.analyze_entry(entry)
        
    for _ in range(10):
        entry = {
            "request_line": "GET /missing HTTP/1.1",
            "client_ip": ip,
            "timestamp": "25/Feb/2026:12:00:01",
            "status_code": "404"
        }
        analyzer.analyze_entry(entry)

    entry_spike = {
        "request_line": "GET /missing HTTP/1.1",
        "client_ip": ip,
        "timestamp": "25/Feb/2026:12:00:01",
        "status_code": "404"
    }
    flags_spike = analyzer.analyze_entry(entry_spike)
    assert any(f.label == "Automated Scanning / Directory Busting" for f in flags_spike)

def test_security_analyzer_exfiltration_and_bots():
    profile = SecurityThreatProfile(size_limit_mb=10)
    analyzer = SecurityAnalyzer(profile)
    ip = "1.2.3.4"
    
    entry_ua = {
        "client_ip": ip,
        "user_agent": "sqlmap/1.0"
    }
    flags_ua = analyzer.analyze_entry(entry_ua)
    assert any(f.label == "Suspicious Tooling" for f in flags_ua)
    
    entry_big = {
        "client_ip": ip,
        "response_bytes": str(15 * 1024 * 1024)
    }
    flags_big = analyzer.analyze_entry(entry_big)
    assert any(f.label == "Large Response / Potential Exfiltration" for f in flags_big)

from unittest.mock import MagicMock, patch

@patch('src.access_parser.security.geo.GeoResolver.resolve')
def test_security_analyzer_geographic_anomaly(mock_resolve):
    profile = SecurityThreatProfile(whitelist_countries=["US", "CA"])
    analyzer = SecurityAnalyzer(profile)
    
    # Valid country
    mock_resolve.return_value = {"country": "US", "city": "Austin"}
    flags_us = analyzer.analyze_entry({"client_ip": "8.8.8.8"})
    assert len(flags_us) == 0
    
    # Invalid country
    mock_resolve.return_value = {"country": "RU", "city": "Moscow"}
    flags_ru = analyzer.analyze_entry({"client_ip": "1.2.3.4"})
    assert any(f.label == "Geographic Anomaly (Traffic from RU)" for f in flags_ru)
    assert flags_ru[0].threat_type == ThreatType.GEOGRAPHIC
