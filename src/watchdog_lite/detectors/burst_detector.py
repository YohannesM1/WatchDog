import time
from collections import deque, defaultdict
from typing import Optional, Dict

class BurstDetector:
    
    rule_id = "BURST"

    def __init__(self, key_field: str = "src_ip", threshold: int = 5, window_sec: int = 60):
        self.key_field = key_field
        self.threshold = threshold
        self.window_sec = window_sec
        self._buckets = defaultdict(deque)

    def _gc(self, dq: deque, now: float):
        cutoff = now - self.window_sec
        while dq and dq[0] < cutoff:
            dq.popleft()

    def feed_alert(self, alert: Dict) -> Optional[Dict]:

        key = alert.get(self.key_field)
        if key is None:
            return None

        now = time.time()
        dq = self._buckets[key]
        self._gc(dq, now)
        dq.append(now)
        self._gc(dq, now)

        if len(dq) >= self.threshold:
            return {
                "rule_id": self.rule_id,
                "severity": "high",
                "kind": "burst_threshold",
                "key_field": self.key_field,
                "key": key,
                "count": len(dq),
                "window_sec": self.window_sec,
                "msg": f"Burst: {len(dq)} events for {key} within {self.window_sec}s",
            }
        return None
