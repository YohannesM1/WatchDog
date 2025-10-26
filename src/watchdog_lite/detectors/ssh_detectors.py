import re
from typing import Optional, Dict
from .base import BaseDetector, Alert

FAILED_RE = re.compile(
    r'Failed password for (?:(invalid user )?(?P<user>\S+)) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)
ACCEPTED_RE = re.compile(
    r'Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

class SSHFailedDetector(BaseDetector):
    rule_id = "SSH_FAIL"
    def feed(self, line: str) -> Optional[Dict]:
        m = FAILED_RE.search(line)
        if not m:
            return None
        return Alert({
            "rule_id": self.rule_id,
            "severity": "medium",
            "kind": "ssh_failed_login",
            "user": m.group("user"),
            "src_ip": m.group("ip"),
            "msg": "Failed SSH password",
        })

class SSHAcceptedDetector(BaseDetector):
    rule_id = "SSH_OK"
    def feed(self, line: str) -> Optional[Dict]:
        m = ACCEPTED_RE.search(line)
        if not m:
            return None
        return Alert({
            "rule_id": self.rule_id,
            "severity": "low",
            "kind": "ssh_login",
            "user": m.group("user"),
            "src_ip": m.group("ip"),
            "msg": "Accepted SSH password",
        })
