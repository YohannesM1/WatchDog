#!/usr/bin/env python3
import subprocess, sys, time
from collections import deque
from datetime import datetime, timedelta
from detectors.sudo_detector import SudoDetector

def alert_fn(rule: str, message: str, meta: dict):
    # central hook: later we can route to Slack/SNS; for now just print JSON
    import json, time
    print(json.dumps({"ts": time.time(), "kind": rule, "message": message, "meta": meta}))

# --- Load optional config file ---
import json, os
try:
    with open("watchdog.config.json", "r") as f:
        cfg = json.load(f)
except FileNotFoundError:
    cfg = None

# --- Instantiate detector with config ---
sudo_detector = SudoDetector(cfg=cfg, alert_fn=alert_fn)

# Filter for likely security-related log lines
predicate = (
    'eventMessage CONTAINS[c] "Failed password" '
    'OR eventMessage CONTAINS[c] "Accepted " '
    'OR process == "sshd" '
    'OR process == "sudo" '
    'OR eventMessage CONTAINS[c] "sudo:" '
    'OR eventMessage CONTAINS[c] "SENTINEL_TEST"'
)
cmd = ["log", "stream", "--style", "syslog", "--predicate", predicate]

# Burst detection settings
WINDOW_SECONDS = 60
THRESHOLD = 5

# Queue of timestamps for recent failures
fails = deque()
start_ts = datetime.now()  # mark when script started
WARMUP_SECONDS = 3  # ignore initial backlog for 3 seconds


def prune(now):
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    while fails and fails[0] < cutoff:
        fails.popleft()

with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as proc:
    try:
        for line in proc.stdout:
            line = line.rstrip()
            now = datetime.now()

            # 1) SUDO detector (parse + rules)
            ev = sudo_detector.parse(line)
            if ev:
                sudo_detector.on_event(ev)

            # 2) Existing SSH fail-burst detector
            counting_enabled = (now - start_ts).total_seconds() >= WARMUP_SECONDS
            if "Failed password" in line and counting_enabled:
                fails.append(now)
                prune(now)
                if len(fails) >= THRESHOLD:
                    print(f"ALERT: Fail burst detected — {len(fails)} failures within {WINDOW_SECONDS}s")
                    fails.clear()  # simple cooldown

            # 3) Optional: echo lines you care about (for debugging)
            if (
                ("Failed password" in line)
                or ("Accepted " in line)
                or (" sshd[" in line)
                or (" sudo" in line)     # catches lines with ' sudo' in the middle
                or ("sudo:" in line)     # <— add this so lines starting with 'sudo:' are shown
                or ("SENTINEL_TEST" in line)
            ):
                print(line)


    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)
