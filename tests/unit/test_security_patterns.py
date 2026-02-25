import pytest
from src.access_parser.security.patterns import PatternMatcher

def test_path_traversal_detection():
    matcher = PatternMatcher()
    results = matcher.scan_request_line("GET /../../../etc/passwd HTTP/1.1")
    labels = [r[0] for r in results]
    assert "Path Traversal Attempt" in labels

def test_xss_detection():
    matcher = PatternMatcher()
    results = matcher.scan_request_line("GET /search?q=<script>alert(1)</script> HTTP/1.1")
    labels = [r[0] for r in results]
    assert "XSS Attempt" in labels

def test_sqli_detection():
    matcher = PatternMatcher()
    results = matcher.scan_request_line("GET /login?user=admin' OR '1'='1' HTTP/1.1")
    labels = [r[0] for r in results]
    assert "SQL Injection Attempt" in labels

def test_no_injection():
    matcher = PatternMatcher()
    results = matcher.scan_request_line("GET /home HTTP/1.1")
    assert len(results) == 0
