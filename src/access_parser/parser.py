import re
from datetime import datetime
from typing import Dict, Optional

class LogParser:
    """
    Core log parser for standard Apache/Nginx combined log format.
    """
    # Example: 127.0.0.1 - - [25/Feb/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "http://referrer.com" "Mozilla/5.0"
    COMBINED_PATTERN = re.compile(
        r'(?P<client_ip>\S+) \S+ \S+ \[(?P<timestamp>.*?)\] '
        r'"(?P<request_line>.*?)" (?P<status_code>\d{3}) (?P<response_bytes>\S+) '
        r'"(?P<referrer>.*?)" "(?P<user_agent>.*?)"'
    )

    def parse_line(self, line: str) -> Optional[Dict]:
        match = self.COMBINED_PATTERN.match(line)
        if not match:
            return None
            
        data = match.groupdict()
        # Clean timestamp (strip timezone for simplicity in this project)
        if "timestamp" in data:
            data["timestamp"] = data["timestamp"].split(" ")[0]
        return data
