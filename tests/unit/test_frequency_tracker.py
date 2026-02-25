import pytest
import time
from collections import deque
from src.access_parser.security.trackers import IPActivityTracker

def test_ip_frequency_tracking():
    tracker = IPActivityTracker(frequency_threshold=5, window_seconds=1)
    
    # Send 5 requests at the same timestamp
    now = time.time()
    for _ in range(5):
        assert tracker.add_request(now) is True
        
    # 6th request should be flagged
    assert tracker.add_request(now) is False

def test_sliding_window_expiration():
    tracker = IPActivityTracker(frequency_threshold=2, window_seconds=1)
    
    now = time.time()
    # Send 2 requests
    tracker.add_request(now)
    tracker.add_request(now)
    
    # 3rd request should be blocked
    assert tracker.add_request(now) is False
    
    # Wait for window to expire
    # Use a future timestamp instead of real sleep for speed
    future = now + 1.1
    
    # Now should be allowed again
    assert tracker.add_request(future) is True

def test_status_code_spike_detection():
    # Use a larger baseline window so it doesn't shift too fast
    tracker = IPActivityTracker(anomaly_multiplier=5, baseline_window=100)
    
    # Establish a baseline of 2% error rate (2 errors in 100 requests)
    for _ in range(98):
        tracker.add_status_code(200)
    for _ in range(2):
        tracker.add_status_code(404)
    
    # Threshold is max(0.02 * 5, 0.1) = 0.1
    # Check for a spike. Since baseline is 2%, a single error in a small window might flag.
    # If we have 1 error in 0 (empty recent), current_rate is 1/1 = 1.0. 1.0 > 0.1.
    assert tracker.check_for_spike(404) is True
