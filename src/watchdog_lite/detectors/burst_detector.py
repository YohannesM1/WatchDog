# detectors/burst_detector.py
import time
from collections import deque, defaultdict
from typing import Optional, Dict

class BurstDetector:
    """
    Sliding-window counter for alerts: if N alerts for the same key happen
    within window_sec, emit a high-severity burst alert.
    Feed it *alerts* (dicts), not raw log lines.
    """
    rule_id = "BURST"

    def __init__(self, key_field: str = "src_ip", threshold: int = 5, window_sec: int = 60):
        self.key_field = key_field
        self.threshold = threshold
        self.window_sec = window_sec
        self._buckets = defaultdict(deque)  # key -> deque[timestamps]

    def _gc(self, dq: deque, now: float):
        cutoff = now - self.window_sec
        while dq and dq[0] < cutoff:
            dq.popleft()

    def feed_alert(self, alert: Dict) -> Optional[Dict]:
        """
        Returns a new 'burst' alert dict when threshold is crossed, else None.
        """
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
