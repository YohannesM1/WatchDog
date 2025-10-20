
## Overview

The goal:  
> “Read system logs in real time and print alerts when something suspicious happens — such as repeated failed logins or abnormal sudo behavior.”

This project is part of my hands-on learning toward cloud security and threat detection — similar in concept to lightweight SIEM agents or custom CloudWatch-based monitors.

---

## Key Features

- Live log streaming via `log stream` (macOS)
- Modular detectors: `SSHFailedDetector`, `SudoDetector`, and `BurstDetector`
- Alert system with severity levels (`low`, `medium`, `high`)
- Clean Rich-based command-line interface with timestamps
- Burst detection: triggers alerts for 5+ failed attempts in 60 seconds
- Graceful shutdown and safe subprocess handling

---

## Installation (macOS)

```bash
git clone https://github.com/YohannesMekuria/WatchDog-Lite.git
cd WatchDog-Lite
pip install -e .
```

Run WatchDog from anywhere:
```bash
watchdog
```

---

## CLI Options

| Flag | Description |
|------|--------------|
| `--version` | Show the current version |
| `--no-color` | Disable colored Rich output |
| `--output <file>` | Save alerts to a custom JSONL file |
| `--debug` | Show all log lines, not just filtered ones |

---

## Example Output

```text
╭──────────────────────────────────╮
│ WatchDog Security Monitor        │
│ Listening for SSH/Sudo events... │
╰──────────────────────────────────╯
[17:42:11] Accepted password for demo from 10.0.0.5 port 51234 ssh2
[17:42:13] sudo: demo : incorrect password attempts (2)
⚠ WatchDog stopped by user.
```

---

## Project Structure

```
WatchDog/
├── output/
│   └── alerts.jsonl
├── pyproject.toml
├── README.md
└── src/
    └── watchdog_lite/
        ├── __init__.py
        ├── __main__.py
        ├── cli.py
        └── detectors/
            ├── __init__.py
            ├── base.py
            ├── burst_detector.py
            ├── ssh_detectors.py
            └── sudo_detector.py
```

---

## Technical Highlights

- Python packaging with `pyproject.toml` and editable install support
- Real-time log stream parsing using `subprocess`
- Command-line interface with optional color and formatting
- Proper signal handling (`proc.terminate()` and `KeyboardInterrupt`)
- Structured JSONL alert output for downstream integrations

---

## Future Plans

- Add Linux syslog support (`/var/log/auth.log`)
- Integrate with AWS CloudWatch or S3 for remote storage
- Add configuration profiles (`watchdog.config.json`)
- Implement anomaly scoring and correlation detection

---

## Author

**Yohannes Mekuria**  
Cloud Security & Threat Detection Trainee  
Based in Canada | Building security tools with Python and AWS  
LinkedIn: [linkedin.com/in/yohannesmekuria](https://www.linkedin.com/in/yohannesmekuria)