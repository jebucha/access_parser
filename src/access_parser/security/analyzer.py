from typing import List, Dict
from datetime import datetime

from .models import ThreatType, Severity, SecurityFlag, SecurityThreatProfile
from .patterns import PatternMatcher
from .trackers import IPActivityTracker
from .geo import GeoResolver

class SecurityAnalyzer:
    def __init__(self, profile: SecurityThreatProfile):
        self.profile = profile
        self.ip_trackers: Dict[str, IPActivityTracker] = {}
        self.matcher = PatternMatcher()
        self.geo_resolver = GeoResolver(profile.geoip_db_path)

    def _get_tracker(self, client_ip: str) -> IPActivityTracker:
        if client_ip not in self.ip_trackers:
            self.ip_trackers[client_ip] = IPActivityTracker(
                frequency_threshold=self.profile.frequency_threshold,
                anomaly_multiplier=self.profile.anomaly_threshold
            )
        return self.ip_trackers[client_ip]

    def analyze_entry(self, entry: Dict) -> List[SecurityFlag]:
        """
        Analyzes a single log entry and returns a list of detected security flags.
        """
        flags = []
        client_ip = entry.get("client_ip", "0.0.0.0")
        tracker = self._get_tracker(client_ip)
        
        # US1: Injection Attacks
        request_line = entry.get("request_line", "")
        matches = self.matcher.scan_request_line(request_line)
        for label, _ in matches:
            flags.append(SecurityFlag(
                label=label,
                severity=Severity.HIGH,
                threat_type=ThreatType.INJECTED
            ))
            
        # US2: Automated Traffic & Brute Force
        timestamp = entry.get("timestamp")
        if timestamp:
            ts_float = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S").timestamp()
            
            # US3: Inhuman speed (sub-100ms) - Check BEFORE updating tracker
            delta = tracker.calculate_time_delta(ts_float)
            if delta is not None and delta < 0.1:
                flags.append(SecurityFlag(
                    label="Inhuman Speed / Automated Script",
                    severity=Severity.MEDIUM,
                    threat_type=ThreatType.AUTOMATED
                ))

            if not tracker.add_request(ts_float):
                flags.append(SecurityFlag(
                    label="High Frequency / Potential DoS",
                    severity=Severity.MEDIUM,
                    threat_type=ThreatType.AUTOMATED
                ))
        
        # US2: Status Code Spikes
        status_code = entry.get("status_code")
        if status_code:
            status_int = int(status_code)
            if tracker.check_for_spike(status_int):
                flags.append(SecurityFlag(
                    label="Automated Scanning / Directory Busting",
                    severity=Severity.MEDIUM,
                    threat_type=ThreatType.AUTOMATED
                ))
            tracker.add_status_code(status_int)

        # US3: Data Exfiltration (Baseline-aware size flagging)
        response_bytes = entry.get("response_bytes")
        if response_bytes and response_bytes != "-":
            size_int = int(response_bytes)
            avg_size = tracker.get_average_response_size()
            stddev = tracker.get_response_size_stddev()
            
            # Flag if > threshold (default 50MB) OR > avg + 3*stddev (if baseline exists)
            limit_bytes = self.profile.size_limit_mb * 1024 * 1024
            if size_int > limit_bytes:
                 flags.append(SecurityFlag(
                    label="Large Response / Potential Exfiltration",
                    severity=Severity.HIGH,
                    threat_type=ThreatType.EXFILTRATION,
                    metadata={"size": size_int, "reason": "Above hard limit"}
                ))
            elif avg_size > 0 and size_int > avg_size + 3 * stddev and size_int > 1024*1024:
                flags.append(SecurityFlag(
                    label="Large Response / Potential Exfiltration",
                    severity=Severity.MEDIUM,
                    threat_type=ThreatType.EXFILTRATION,
                    metadata={"size": size_int, "reason": "Anomaly from baseline"}
                ))
            tracker.add_response_size(size_int)

        # US3: User-Agent Validation
        user_agent = entry.get("user_agent")
        if user_agent:
            suspicious_bots = ["sqlmap", "nmap", "python-requests", "curl"]
            if any(bot in user_agent.lower() for bot in suspicious_bots):
                flags.append(SecurityFlag(
                    label="Suspicious Tooling",
                    severity=Severity.LOW,
                    threat_type=ThreatType.AUTOMATED,
                    metadata={"user_agent": user_agent}
                ))

        # US4: Geographic Anomaly Detection
        location = self.geo_resolver.resolve(client_ip)
        if location:
            country_code = location.get("country")
            if self.profile.whitelist_countries and country_code not in self.profile.whitelist_countries:
                flags.append(SecurityFlag(
                    label=f"Geographic Anomaly (Traffic from {country_code})",
                    severity=Severity.LOW,
                    threat_type=ThreatType.GEOGRAPHIC,
                    metadata={"location": location}
                ))
        
        return flags
