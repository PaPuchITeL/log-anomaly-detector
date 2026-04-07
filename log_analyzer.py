import argparse
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path


FAILED_LOGIN_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:\[\d+\])?:\s+"
    r"Failed password for (?:invalid user )?(?P<username>\S+) from (?P<ip>\S+)"
)

SUCCESS_LOGIN_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:\[\d+\])?:\s+"
    r"Accepted (?:password|publickey) for (?P<username>\S+) from (?P<ip>\S+)"
)


def parse_timestamp(timestamp_text, year):
    """Convert Linux log timestamps into a full datetime using the chosen year."""
    full_timestamp = f"{year} {timestamp_text}"
    return datetime.strptime(full_timestamp, "%Y %b %d %H:%M:%S")


def parse_log_line(line, year):
    """Extract only SSH login events that matter for this small SOC project."""
    failed_match = FAILED_LOGIN_PATTERN.search(line)
    if failed_match:
        event_time = parse_timestamp(failed_match.group("timestamp"), year)
        return {
            "timestamp": event_time,
            "username": failed_match.group("username"),
            "ip": failed_match.group("ip"),
            "status": "failure",
        }

    success_match = SUCCESS_LOGIN_PATTERN.search(line)
    if success_match:
        event_time = parse_timestamp(success_match.group("timestamp"), year)
        return {
            "timestamp": event_time,
            "username": success_match.group("username"),
            "ip": success_match.group("ip"),
            "status": "success",
        }

    return None


def parse_log_file(file_path, year):
    events = []

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            parsed_event = parse_log_line(line.strip(), year)
            if parsed_event:
                events.append(parsed_event)

    return events


def create_event_finding(event):
    """Store basic login activity so the JSON file also shows normal events."""
    if event["status"] == "failure":
        return {
            "timestamp": event["timestamp"].isoformat(sep=" "),
            "username": event["username"],
            "ip": event["ip"],
            "event_type": "failed_login",
            "reason": "Failed login attempt found in SSH logs.",
            "label": "suspicious",
        }

    return {
        "timestamp": event["timestamp"].isoformat(sep=" "),
        "username": event["username"],
        "ip": event["ip"],
        "event_type": "successful_login",
        "reason": "Successful login found in SSH logs.",
        "label": "normal",
    }


def detect_brute_force(events, threshold):
    """
    Detect repeated failed logins from the same IP.
    Once the threshold is reached, we create one high-severity finding.
    """
    failed_attempts_by_ip = defaultdict(list)
    findings = []
    already_flagged = set()

    for event in events:
        if event["status"] != "failure":
            continue

        ip = event["ip"]
        failed_attempts_by_ip[ip].append(event)

        if len(failed_attempts_by_ip[ip]) >= threshold and ip not in already_flagged:
            usernames = {item["username"] for item in failed_attempts_by_ip[ip]}
            username_value = usernames.pop() if len(usernames) == 1 else "multiple_users"

            findings.append(
                {
                    "timestamp": event["timestamp"].isoformat(sep=" "),
                    "username": username_value,
                    "ip": ip,
                    "event_type": "brute_force_attempt",
                    "reason": f"{len(failed_attempts_by_ip[ip])} failed logins from the same IP reached the threshold of {threshold}.",
                    "label": "critical",
                }
            )
            already_flagged.add(ip)

    return findings


def detect_account_compromise(events, threshold):
    """
    Detect a possible compromise: many failed attempts followed by a success.
    We track failures by both IP and username to keep the logic realistic but simple.
    """
    failed_attempts_by_user_and_ip = defaultdict(int)
    findings = []

    for event in events:
        key = (event["ip"], event["username"])

        if event["status"] == "failure":
            failed_attempts_by_user_and_ip[key] += 1
            continue

        if failed_attempts_by_user_and_ip[key] >= threshold:
            findings.append(
                {
                    "timestamp": event["timestamp"].isoformat(sep=" "),
                    "username": event["username"],
                    "ip": event["ip"],
                    "event_type": "account_compromise",
                    "reason": f"Successful login happened after {failed_attempts_by_user_and_ip[key]} failed attempts from the same IP.",
                    "label": "critical",
                }
            )

    return findings


def is_night_hour(hour, night_start, night_end):
    """Support both normal ranges and ranges that cross midnight."""
    if night_start < night_end:
        return night_start <= hour < night_end

    return hour >= night_start or hour < night_end


def detect_unusual_hour_logins(events, night_start, night_end):
    """Flag successful logins during night hours as suspicious."""
    findings = []

    for event in events:
        if event["status"] != "success":
            continue

        event_hour = event["timestamp"].hour
        if is_night_hour(event_hour, night_start, night_end):
            findings.append(
                {
                    "timestamp": event["timestamp"].isoformat(sep=" "),
                    "username": event["username"],
                    "ip": event["ip"],
                    "event_type": "unusual_hour_login",
                    "reason": f"Successful login happened during unusual hours ({night_start}:00-{night_end}:00).",
                    "label": "suspicious",
                }
            )

    return findings


def analyze_logs(log_files, threshold, night_start, night_end, year):
    all_events = []

    for log_file in log_files:
        all_events.extend(parse_log_file(log_file, year))

    all_events.sort(key=lambda event: event["timestamp"])

    findings = [create_event_finding(event) for event in all_events]
    findings.extend(detect_brute_force(all_events, threshold))
    findings.extend(detect_account_compromise(all_events, threshold))
    findings.extend(detect_unusual_hour_logins(all_events, night_start, night_end))

    findings.sort(key=lambda finding: finding["timestamp"])
    return findings


def save_findings(findings, output_path):
    output_file_path = Path(output_path)
    output_file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file_path, "w", encoding="utf-8") as output_file:
        json.dump(findings, output_file, indent=4)


def build_argument_parser():
    parser = argparse.ArgumentParser(description="Simple SOC-style Linux log analyzer.")
    parser.add_argument(
        "log_files",
        nargs="+",
        help="Paths to auth.log, syslog, or other Linux log files.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="findings.json",
        help="JSON file used to save the findings.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Number of failed logins needed before brute-force and compromise alerts.",
    )
    parser.add_argument(
        "--night-start",
        type=int,
        default=22,
        help="Hour when unusual login time starts.",
    )
    parser.add_argument(
        "--night-end",
        type=int,
        default=6,
        help="Hour when unusual login time ends.",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=datetime.now().year,
        help="Year used when parsing Linux log timestamps.",
    )
    return parser


def main():
    parser = build_argument_parser()
    args = parser.parse_args()

    findings = analyze_logs(
        log_files=args.log_files,
        threshold=args.threshold,
        night_start=args.night_start,
        night_end=args.night_end,
        year=args.year,
    )

    save_findings(findings, args.output)
    print(f"Saved {len(findings)} findings to {args.output}")


if __name__ == "__main__":
    main()
