import pytest
from src.access_parser.security.analyzer import SecurityAnalyzer
from src.access_parser.security.models import SecurityThreatProfile, ThreatType

def test_response_size_baseline_flagging():
    profile = SecurityThreatProfile(size_limit_mb=10) # 10MB default
    analyzer = SecurityAnalyzer(profile)
    
    # Establish a baseline of 100KB responses
    for _ in range(20):
        analyzer.analyze_entry({"response_bytes": "102400", "client_ip": "1.1.1.1"})
        
    # Standard deviation of constant is 0. 
    # If we add a 11MB response, it should be flagged (above 10MB limit)
    entry_big = {"response_bytes": str(11 * 1024 * 1024), "client_ip": "1.1.1.1"}
    flags = analyzer.analyze_entry(entry_big)
    assert any(f.label == "Large Response / Potential Exfiltration" for f in flags)

def test_user_agent_validation():
    profile = SecurityThreatProfile()
    analyzer = SecurityAnalyzer(profile)
    
    # Known bot in UA
    entry_bot = {"user_agent": "sqlmap/1.4.11#stable (http://sqlmap.org)", "client_ip": "2.2.2.2"}
    flags = analyzer.analyze_entry(entry_bot)
    assert any(f.label == "Suspicious Tooling" for f in flags)
    
    # Generic bot
    entry_generic = {"user_agent": "python-requests/2.25.1", "client_ip": "2.2.2.2"}
    flags_generic = analyzer.analyze_entry(entry_generic)
    assert any(f.label == "Suspicious Tooling" for f in flags_generic)
