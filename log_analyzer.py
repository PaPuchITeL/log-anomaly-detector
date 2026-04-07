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
    """Return one normalized login record or None if the line is not an SSH login event."""
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
    """Read one file and collect only the login records we care about."""
    records = []

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            parsed_record = parse_log_line(line.strip(), year)
            if parsed_record:
                records.append(parsed_record)

    return records


def load_log_records(log_files, year):
    """Load and sort records from all provided log files."""
    all_records = []

    for log_file in log_files:
        all_records.extend(parse_log_file(log_file, year))

    all_records.sort(key=lambda record: record["timestamp"])
    return all_records


def build_detection_event(timestamp, event_type, ip, username, severity, reason):
    """Create a simple SOC-style event dictionary for JSON output."""
    return {
        "timestamp": timestamp.isoformat(sep=" "),
        "event_type": event_type,
        "ip": ip,
        "username": username,
        "severity": severity,
        "reason": reason,
    }


def detect_failed_logins(records):
    """
    Turn each failed login into a low-severity event.
    A single failure is not always an attack, but analysts still record it.
    """
    detected_events = []

    for record in records:
        if record["status"] == "failure":
            detected_events.append(
                build_detection_event(
                    timestamp=record["timestamp"],
                    event_type="failed_login",
                    ip=record["ip"],
                    username=record["username"],
                    severity="low",
                    reason="Single failed login attempt seen in the SSH logs.",
                )
            )

    return detected_events


def detect_brute_force(records, threshold):
    """
    Detect repeated failed logins from the same IP.
    If one IP goes above the threshold, we create one medium-severity brute-force event.
    """
    failed_attempts_by_ip = defaultdict(list)
    detected_events = []
    already_flagged = set()

    for record in records:
        if record["status"] != "failure":
            continue

        ip = record["ip"]
        failed_attempts_by_ip[ip].append(record)
        attempt_count = len(failed_attempts_by_ip[ip])

        if attempt_count > threshold and ip not in already_flagged:
            usernames = {item["username"] for item in failed_attempts_by_ip[ip]}
            username_value = usernames.pop() if len(usernames) == 1 else "multiple_users"

            detected_events.append(
                build_detection_event(
                    timestamp=record["timestamp"],
                    event_type="brute_force",
                    ip=ip,
                    username=username_value,
                    severity="medium",
                    reason=f"{attempt_count} failed logins came from the same IP. This is above the threshold of {threshold}.",
                )
            )
            already_flagged.add(ip)

    return detected_events


def detect_account_compromise(records, threshold):
    """
    Detect a possible compromise when repeated failures are followed by a success.
    We track failures by both IP and username so the success matches the same account attempt.
    """
    failed_attempts_by_user_and_ip = defaultdict(int)
    detected_events = []
    already_flagged = set()

    for record in records:
        key = (record["ip"], record["username"])

        if record["status"] == "failure":
            failed_attempts_by_user_and_ip[key] += 1
            continue

        if failed_attempts_by_user_and_ip[key] > threshold and key not in already_flagged:
            attempt_count = failed_attempts_by_user_and_ip[key]
            detected_events.append(
                build_detection_event(
                    timestamp=record["timestamp"],
                    event_type="account_compromise",
                    ip=record["ip"],
                    username=record["username"],
                    severity="high",
                    reason=f"Successful login happened after {attempt_count} failed attempts from the same IP and username.",
                )
            )
            already_flagged.add(key)

    return detected_events


def analyze_logs(log_files, threshold, year):
    records = load_log_records(log_files, year)
    detected_events = []

    detected_events.extend(detect_failed_logins(records))
    detected_events.extend(detect_brute_force(records, threshold))
    detected_events.extend(detect_account_compromise(records, threshold))

    detected_events.sort(key=lambda event: event["timestamp"])
    return detected_events


def save_events(detected_events, output_path):
    output_file_path = Path(output_path)
    output_file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file_path, "w", encoding="utf-8") as output_file:
        json.dump(detected_events, output_file, indent=4)


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
        help="Brute-force and compromise are flagged when failed logins go above this value.",
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

    detected_events = analyze_logs(
        log_files=args.log_files,
        threshold=args.threshold,
        year=args.year,
    )

    save_events(detected_events, args.output)
    print(f"Saved {len(detected_events)} detected events to {args.output}")


if __name__ == "__main__":
    main()
