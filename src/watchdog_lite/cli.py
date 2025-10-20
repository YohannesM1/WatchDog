#!/usr/bin/env python3
import subprocess, sys, time
from datetime import datetime
from .detectors.sudo_detector import SudoDetector
from .detectors.ssh_detectors import SSHFailedDetector, SSHAcceptedDetector
from .detectors.burst_detector import BurstDetector
import argparse
from watchdog_lite import __version__

parser = argparse.ArgumentParser()
parser.add_argument('--version', action='version', version=f'watchdog-lite {__version__}')
parser.add_argument('--no-color', action='store_true', help="Disable colored Rich output")
parser.add_argument('--output', type=str, help="Custom output file (default: output/alerts.jsonl)")

args = parser.parse_args()

# Apply user flags
if args.no_color:
    PRETTY = False

if args.output:
    OUT_FILE = args.output

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH = True
    console = Console()
    if RICH:
        console.print(Panel.fit(
            "[bold cyan]WatchDog Security Monitor[/bold cyan]\n"
            "Listening for SSH/Sudo events...",
            border_style="cyan"
        ))
    else:
        print("WatchDog running (plain mode, no colors)")


except Exception:
    RICH = False
    console = None

# Enable / disable rich panels
PRETTY = True

# Default severities if detectors don't specify one
RULE_SEVERITY = {
    "BURST": "high",
    "SSH_FAIL": "medium",
    "SSH_OK": "low",
    "SUDO_FAIL_STREAK": "high",
    "SUDO_FAIL_THEN_SUCCESS": "high",
    "SUDO_FIRST_TIME_USER": "low",
    "SUDO_NO_TTY": "medium",
    "SUDO_SENSITIVE_CMD": "high",
}

SEV_COLOR = {"low": "green", "medium": "yellow", "high": "red"}

import os, json
OUT_FILE = os.environ.get("WD_OUT", "output/alerts.jsonl")

def alert_sink(rule: str, message: str, meta: dict):
    """Unified output for all detectors (pretty panel + JSONL)."""
    rec = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "rule_id": rule,
        "message": message,
        **meta,
    }
    sev = rec.get("severity") or RULE_SEVERITY.get(rule, "low")
    rec["severity"] = sev

    if PRETTY and RICH and console:
        tbl = Table(show_header=False, expand=True)
        for k, v in rec.items():
            if k == "message":
                continue
            tbl.add_row(str(k), str(v))
        color = SEV_COLOR.get(sev, "white")
        console.print(Panel(tbl, title=f"[{color}]{rule} [{sev.upper()}]", subtitle=message, expand=True))

    print(json.dumps(rec))

    os.makedirs(os.path.dirname(OUT_FILE) or ".", exist_ok=True)
    with open(OUT_FILE, "a") as f:
        f.write(json.dumps(rec) + "\n")

# --- Load optional config file ---
try:
    with open("watchdog.config.json", "r") as f:
        cfg = json.load(f)
except FileNotFoundError:
    cfg = None

# --- Instantiate detectors ---
sudo_detector = SudoDetector(cfg=cfg, alert_fn=alert_sink)

ssh_fail = SSHFailedDetector()
ssh_ok   = SSHAcceptedDetector()
feed_detectors = [ssh_fail, ssh_ok]

# Burst detector (by source IP)
burster = BurstDetector(key_field="src_ip", threshold=5, window_sec=60)

# Filter for likely security-related log lines
predicate = (
    'eventMessage CONTAINS[c] "Failed password" '
    'OR eventMessage CONTAINS[c] "Accepted " '
    'OR process == "sshd" '
    'OR process == "sudo" '
    'OR eventMessage CONTAINS[c] "sudo:" '
    'OR eventMessage CONTAINS[c] "SENTINEL_TEST"'
)

def main():
    cmd = ["log", "stream", "--style", "syslog", "--predicate", predicate]

    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as proc:
        try:
            for line in proc.stdout:
                line = line.rstrip()
                now = datetime.now()

                # A) SSH detectors (feed -> may return dict alert)
                for d in feed_detectors:
                    alert = d.feed(line)
                    if alert:
                        # normalize to the unified sink
                        msg = alert.pop("msg", "")
                        rule = alert.pop("rule_id", "RULE")
                        alert_sink(rule, msg, alert)

                        # B) Feed the same alert into the burst detector
                        burst = burster.feed_alert({**alert, "rule_id": rule})
                        if burst:
                            bmsg  = burst.pop("msg", "")
                            brule = burst.pop("rule_id", "BURST")
                            alert_sink(brule, bmsg, burst)

                # 1) SUDO detector (parse + rules)
                ev = sudo_detector.parse(line)
                if ev:
                    sudo_detector.on_event(ev)

                # 3) Optional: echo lines you care about (for debugging)
                if (
                    ("Failed password" in line)
                    or ("Accepted " in line)
                    or (" sshd[" in line)
                    or (" sudo" in line)     # catches lines with ' sudo' in the middle
                    or ("sudo:" in line)     # <— add this so lines starting with 'sudo:' are shown
                    or ("SENTINEL_TEST" in line)
                ):
                    print(f"[{now:%H:%M:%S}] {line}")

        except KeyboardInterrupt:
            if RICH and console:
                console.print("\n[yellow]⚠ WatchDog stopped by user.[/yellow]")
            else:
                print("\nWatchDog stopped.")
                # kill subprocess before exit
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
            sys.exit(0)

def run():
    """Entry point for console script."""
    main()

if __name__ == "__main__":
    run()
