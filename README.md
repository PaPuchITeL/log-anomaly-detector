# Log Anomaly Detector

This is a small Python project that simulates how a junior SOC analyst might review Linux login logs.

## Features

- Parses Linux `auth.log` and `syslog` style SSH login events
- Separates parsing logic from detection logic
- Creates SOC-style event dictionaries instead of only printing text
- Detects single failed logins as low-severity events
- Detects brute-force activity when failed logins from one IP go above the threshold
- Detects a possible account compromise when repeated failures are followed by a success
- Saves all detected events to JSON

## Event Format

Each detected event is saved as a dictionary like this:

```json
{
    "timestamp": "2026-04-07 00:15:08",
    "event_type": "brute_force",
    "ip": "203.0.113.50",
    "username": "admin",
    "severity": "medium",
    "reason": "multiple failed logins from the same IP"
}
```

## Severity Levels

- `low`: single failed login
- `medium`: brute-force activity
- `high`: possible account compromise

## Run

```bash
python log_analyzer.py sample_logs/auth.log sample_logs/syslog -o findings.json
```

## Notes

- The script uses only Python standard library modules.
- Linux log timestamps usually do not include a year, so the script adds the current year by default.
- The threshold is `5` by default, and the brute-force rule triggers when failed attempts go above that value.
- The code is intentionally simple and commented so it is easier to explain in an interview.
