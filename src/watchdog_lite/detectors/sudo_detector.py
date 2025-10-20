# detectors/sudo_detector.py
import re
import time
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional, Callable

SUDO_HEAD_RE = re.compile(
    r"sudo(?:\[\d+\])?:\s*(?P<user>\S+)\s*:\s*(?:(?P<fail>\d+)\s+incorrect password attempts?)?\s*;\s*(?P<rest>.*)$",
    re.IGNORECASE,
)

@dataclass
class SudoEvent:
    ts: float
    user: str
    tty: str
    pwd: str
    target: str
    cmd: str
    outcome: str  # "fail" | "success" | "unknown"
    fail_count: int = 0 

DEFAULT_CFG = {
    "fail_streak_threshold": 3,
    "fail_streak_window_sec": 300,        # 5 min
    "fail_then_success_window_sec": 600,  # 10 min
    "sensitive_cmd_patterns": [
        r"useradd|dscl|passwd|chsh",
        r"launchctl|crontab",
        r"ifconfig|route|pfctl|iptables|ssh-keygen|scp",
        r"chmod\s+-R\s+7\d\d|chown\s+-R",
    ],
    "no_tty_values": ["?", "unknown", "notty", "none", ""],
}

class SudoDetector:
    """Parser + rules. Provide alert_fn(rule, message, meta) to receive alerts."""

    def __init__(self, cfg: Optional[dict] = None, alert_fn: Optional[Callable[[str, str, dict], None]] = None):
        # allow passing either the whole config or the "sudo" section
        base = cfg or {}
        if isinstance(base, dict) and "fail_streak_threshold" not in base and "sudo" in base:
            base = base["sudo"]

        self.cfg = {**DEFAULT_CFG, **base}
        self.alert = alert_fn or self._print_alert

        # state
        self.fail_windows = defaultdict(lambda: deque())  # (user, tty) -> deque[timestamps]
        self.first_success_seen = set()

        self.sensitive_res = [re.compile(p) for p in self.cfg["sensitive_cmd_patterns"]]
        self.no_tty = {v.lower() for v in self.cfg["no_tty_values"]}

    # ---------- parsing ----------
    def parse(self, line: str, ts: Optional[float] = None) -> Optional[SudoEvent]:
        m = SUDO_HEAD_RE.search(line.strip())
        if not m:
            return None

        user = m.group("user")
        fail_count = int(m.group("fail")) if m.group("fail") else 0
        had_fail_segment = m.group("fail") is not None
        kv_text = m.group("rest")

        tty = pwd = target = cmd = ""
        parts = [p.strip() for p in kv_text.split(";") if p.strip()]
        for part in parts:
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            k = k.strip().upper()
            v = v.strip()
            if k == "TTY":
                tty = v
            elif k == "PWD":
                pwd = v
            elif k == "USER":
                target = v
            elif k == "COMMAND":
                cmd = v

        outcome = "fail" if fail_count else ("success" if cmd else "unknown")

        return SudoEvent(
            ts=time.time() if ts is None else ts,
            user=user.strip(),
            tty=tty.strip(),
            pwd=pwd.strip(),
            target=target.strip(),
            cmd=cmd.strip(),
            outcome=outcome,
            fail_count=fail_count,
        )

    # ---------- rules ----------
    def on_event(self, ev: SudoEvent):
        key = (ev.user, ev.tty)
        now = ev.ts
        win = self.fail_windows[key]

        # 1) fail streak
        if ev.outcome == "fail":
            count = max(1, ev.fail_count)
            for _ in range(count):
                win.append(now)

            cutoff = now - self.cfg["fail_streak_window_sec"]
            while win and win[0] < cutoff:
                win.popleft()

            if len(win) >= self.cfg["fail_streak_threshold"]:
                self._alert(
                    "SUDO_FAIL_STREAK",
                    f"{ev.user} has {len(win)} sudo failures on {ev.tty} in last {self.cfg['fail_streak_window_sec']}s",
                    {"user": ev.user, "tty": ev.tty, "count": len(win)}
                )
            return  # stop here for fails; success-only rules below

        # success path:
        # 2) fail-then-success within window
        cutoff = now - self.cfg["fail_then_success_window_sec"]
        while win and win[0] < cutoff:
            win.popleft()
        if len(win) >= 2:
            self._alert(
                "SUDO_FAIL_THEN_SUCCESS",
                f"{ev.user} succeeded with sudo after {len(win)} failures within {self.cfg['fail_then_success_window_sec']}s",
                {"user": ev.user, "tty": ev.tty, "recent_fails": len(win), "command": ev.cmd}
            )
            win.clear()

        # 3) first-time sudo success
        if ev.user not in self.first_success_seen:
            self.first_success_seen.add(ev.user)
            self._alert(
                "SUDO_FIRST_TIME_USER",
                f"{ev.user} used sudo successfully for the first time observed",
                {"user": ev.user, "tty": ev.tty, "command": ev.cmd}
            )

        # 4) no/malformed TTY
        if ev.tty.lower() in self.no_tty:
            self._alert(
                "SUDO_NO_TTY",
                f"Sudo success for {ev.user} with unusual/missing TTY ({ev.tty})",
                {"user": ev.user, "tty": ev.tty, "command": ev.cmd}
            )

        # 5) sensitive commands
        for rx in self.sensitive_res:
            if rx.search(ev.cmd):
                self._alert(
                    "SUDO_SENSITIVE_CMD",
                    f"Sudo ran sensitive command: {ev.cmd}",
                    {"user": ev.user, "tty": ev.tty, "command": ev.cmd}
                )
                break

    # ---------- alert helpers ----------
    def _alert(self, rule: str, message: str, meta: dict):
        self.alert(rule, message, meta)

    @staticmethod
    def _print_alert(rule: str, message: str, meta: dict):
        out = {"ts": time.time(), "kind": rule, "message": message, "meta": meta}
        print(json.dumps(out))
