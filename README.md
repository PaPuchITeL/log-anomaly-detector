# Log Anomaly Detector

This is a small Python project that simulates how a junior SOC analyst might review Linux login logs.

## Features

- Parses `auth.log` and `syslog` style SSH login events
- Detects failed login attempts
- Detects brute-force activity when one IP reaches a failed-login threshold
- Detects a possible account compromise when a success follows repeated failures
- Detects successful logins during unusual night hours
- Saves findings to JSON with:
  - `timestamp`
  - `username`
  - `ip`
  - `event_type`
  - `reason`
  - `label`

## Labels

- `normal`: regular successful login
- `suspicious`: failed login or unusual-hour login
- `critical`: brute-force attempt or possible account compromise

## Run

```bash
python log_analyzer.py sample_logs/auth.log sample_logs/syslog -o findings.json
```

## Notes

- The script uses only Python standard library modules.
- Linux log timestamps usually do not include a year, so the script adds the current year by default.
- The code is intentionally simple and commented to keep it suitable for a student project.
