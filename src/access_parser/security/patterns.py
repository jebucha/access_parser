import re
from typing import Dict, List
from .models import ThreatType

class PatternMatcher:
    """
    Utility class for matching log entries against pre-compiled regex signatures.
    """
    DEFAULT_PATTERNS = {
        ThreatType.INJECTED: {
            "Path Traversal Attempt": r"\.\./",
            "XSS Attempt": r"<script.*?>",
            "SQL Injection Attempt": r"SELECT|UNION|OR '1'='1'|INSERT|DELETE|UPDATE"
        }
    }

    def __init__(self, custom_patterns: Dict[str, str] = None):
        self.compiled_patterns = {}
        patterns_to_compile = self.DEFAULT_PATTERNS[ThreatType.INJECTED].copy()
        if custom_patterns:
            patterns_to_compile.update(custom_patterns)
        
        for label, pattern_str in patterns_to_compile.items():
            self.compiled_patterns[label] = re.compile(pattern_str, re.IGNORECASE)

    def scan_request_line(self, request_line: str) -> List[tuple]:
        """
        Scans a request line for all compiled patterns.
        Returns a list of (label, matched_string).
        """
        matches = []
        if not request_line:
            return matches
        
        for label, pattern in self.compiled_patterns.items():
            match = pattern.search(request_line)
            if match:
                matches.append((label, match.group(0)))
        return matches
