import time
from collections import deque
from typing import List, Optional

class IPActivityTracker:
    """
    Tracks request frequency and status code behavior for a specific IP.
    """
    def __init__(self, frequency_threshold: int = 20, window_seconds: int = 1,
                 anomaly_multiplier: int = 5, baseline_window: int = 100):
        self.frequency_threshold = frequency_threshold
        self.window_seconds = window_seconds
        self.anomaly_multiplier = anomaly_multiplier
        self.baseline_window = baseline_window
        
        # Request frequency
        self.request_timestamps = deque()
        self.last_request_time: Optional[float] = None
        
        # Status code baseline
        self.baseline_status_codes = deque(maxlen=baseline_window)
        self.recent_status_codes = deque(maxlen=10) # Short window for current rate
        
        # Response size baseline
        self.response_sizes = deque(maxlen=baseline_window)

    def add_request(self, timestamp: float) -> bool:
        """
        Adds a request timestamp and checks if the rate limit is exceeded.
        Returns True if allowed, False if flagged as high frequency.
        """
        while self.request_timestamps and self.request_timestamps[0] < timestamp - self.window_seconds:
            self.request_timestamps.popleft()
            
        self.request_timestamps.append(timestamp)
        allowed = len(self.request_timestamps) <= self.frequency_threshold
        self.last_request_time = timestamp
        return allowed

    def calculate_time_delta(self, current_timestamp: float) -> Optional[float]:
        if self.last_request_time is None:
            return None
        return current_timestamp - self.last_request_time

    def add_status_code(self, status_code: int):
        self.baseline_status_codes.append(status_code)
        self.recent_status_codes.append(status_code)

    def add_response_size(self, size_bytes: int):
        self.response_sizes.append(size_bytes)
        
    def get_average_response_size(self) -> float:
        if not self.response_sizes:
            return 0.0
        return sum(self.response_sizes) / len(self.response_sizes)

    def get_response_size_stddev(self) -> float:
        if len(self.response_sizes) < 2:
            return 0.0
        avg = self.get_average_response_size()
        variance = sum((x - avg) ** 2 for x in self.response_sizes) / len(self.response_sizes)
        return variance ** 0.5
        
    def check_for_spike(self, status_code: int) -> bool:
        if not self.baseline_status_codes:
            return False
            
        is_error = 400 <= status_code < 600
        if not is_error:
            return False
            
        # Baseline error rate (from the longer window)
        error_count = sum(1 for c in self.baseline_status_codes if 400 <= c < 600)
        baseline_rate = error_count / len(self.baseline_status_codes)
        
        # Current error rate (from the shorter window)
        # We include the incoming status_code conceptually
        recent_errors = sum(1 for c in self.recent_status_codes if 400 <= c < 600)
        current_rate = (recent_errors + 1) / (len(self.recent_status_codes) + 1)
        
        threshold = max(baseline_rate * self.anomaly_multiplier, 0.1)
        
        if current_rate >= threshold:
            return True
        return False
