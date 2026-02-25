import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional

class ThreatType(Enum):
    INJECTED = "Injected"
    AUTOMATED = "Automated"
    GEOGRAPHIC = "Geographic"
    EXFILTRATION = "Exfiltration"

class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class SecurityFlag:
    label: str
    severity: Severity
    threat_type: ThreatType
    metadata: Dict = field(default_factory=dict)

@dataclass
class SecurityThreatProfile:
    patterns: Dict[ThreatType, List[re.Pattern]] = field(default_factory=dict)
    frequency_threshold: int = 20
    anomaly_threshold: int = 5
    size_limit_mb: int = 50
    whitelist_countries: List[str] = field(default_factory=list)
    geoip_db_path: Optional[str] = None
