# detectors/base.py
from typing import Optional, Dict

class Alert(dict):
    """Lightweight alert dict."""
    pass

class BaseDetector:
    rule_id = "BASE"
    def feed(self, line: str) -> Optional[Dict]:
        raise NotImplementedError
