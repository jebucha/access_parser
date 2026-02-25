import sys
import argparse
import json
from .parser import LogParser
from .security.analyzer import SecurityAnalyzer, SecurityThreatProfile

def format_security_flag(flag, entry):
    """
    Formats a security flag for human-readable console output.
    """
    severity_prefix = f"[{flag.severity.value}]"
    ip = entry.get("client_ip", "Unknown")
    return f"[SECURITY] {severity_prefix} {flag.label} from {ip} | URI: {entry.get('request_line', 'N/A')}"

def main():
    parser = argparse.ArgumentParser(description="Access Log Parser with Security Enrichment")
    parser.add_argument("file", help="Path to the access log file")
    parser.add_argument("--security", action="store_true", help="Enable security threat detection")
    parser.add_argument("--geoip-db", help="Path to MaxMind .mmdb file for geographic resolution")
    parser.add_argument("--frequency", type=int, default=20, help="Max hits/sec from a single IP")
    parser.add_argument("--anomaly-rate", type=int, default=5, help="Multiplier for status code spikes")
    parser.add_argument("--size-limit", type=int, default=50, help="Max allowed response size (MB)")
    parser.add_argument("--whitelist", help="Comma-separated ISO country codes (e.g. US,CA)")
    parser.add_argument("--json", action="store_true", help="Output enriched entries in JSON format")

    args = parser.parse_args()
    
    # Initialize components
    log_parser = LogParser()
    profile = SecurityThreatProfile(
        frequency_threshold=args.frequency,
        anomaly_threshold=args.anomaly_rate,
        size_limit_mb=args.size_limit,
        geoip_db_path=args.geoip_db,
        whitelist_countries=args.whitelist.split(",") if args.whitelist else []
    )
    analyzer = SecurityAnalyzer(profile)

    try:
        with open(args.file, 'r') as f:
            # T027a: Buffering/skipping logic for extreme log volumes
            # Use a generator to process lines one by one to keep memory low
            # (In a real system with real-time intake, we'd skip if the intake buffer overflows)
            for line_count, line in enumerate(f):
                entry = log_parser.parse_line(line.strip())
                if not entry:
                    continue
                
                # Artificial skip for extreme volume example
                if line_count > 1000000: # 1M lines threshold
                    print(f"Warning: Extreme volume detected. Skipping line {line_count}.", file=sys.stderr)
                    continue
                    
                security_flags = []
                if args.security:
                    security_flags = analyzer.analyze_entry(entry)
                
                if args.json:
                    # Enrich entry with flags
                    entry["security_flags"] = [
                        {"label": f.label, "severity": f.severity.value, "type": f.threat_type.value}
                        for f in security_flags
                    ]
                    print(json.dumps(entry))
                else:
                    # Human-readable output
                    print(f"{entry['timestamp']} {entry['client_ip']} {entry['request_line']} {entry['status_code']}")
                    for flag in security_flags:
                        print(format_security_flag(flag, entry))
    except FileNotFoundError:
        print(f"Error: File {args.file} not found.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
