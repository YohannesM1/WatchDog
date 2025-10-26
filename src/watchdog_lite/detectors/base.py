from typing import Optional, Dict

class Alert(dict):
    pass

class BaseDetector:
    rule_id = "BASE"
    def feed(self, line: str) -> Optional[Dict]:
        raise NotImplementedError
