#!/usr/bin/env python3
"""Parse Linux authentication logs into timeline CSV.

Supports:
  - /var/log/auth.log (Ubuntu/Debian) - ISO 8601 timestamp format
  - /var/log/secure (RHEL/Fedora, traditional syslog format)
  - journald JSON export (any distro): journalctl --output=json > auth.json
"""

import csv
import datetime
import glob
import json
import re
import sys
from pathlib import Path

FIELDNAMES = [
    "timestamp", "hostname", "process", "pid", "event_type",
    "username", "source_ip", "source_port", "auth_method",
    "target_user", "command", "details", "source_file",
]

# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _filetime_us_to_dt(us: str) -> datetime.datetime:
    """Convert journald __REALTIME_TIMESTAMP (microseconds since epoch) to UTC datetime."""
    return datetime.datetime.fromtimestamp(int(us) / 1_000_000, tz=datetime.timezone.utc)


def _parse_iso_ts(ts: str) -> datetime.datetime | None:
    """Parse ISO 8601 timestamp from Ubuntu auth.log, return UTC datetime."""
    try:
        dt = datetime.datetime.fromisoformat(ts)
        return dt.astimezone(datetime.timezone.utc)
    except ValueError:
        return None


# Traditional syslog format has no year - use the file's mtime year as a best guess
_SYSLOG_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
)}

def _parse_syslog_ts(ts: str, year: int) -> datetime.datetime | None:
    """Parse 'MMM DD HH:MM:SS' syslog timestamp. Assumes UTC (no TZ in format)."""
    try:
        parts = ts.split()
        month = _SYSLOG_MONTHS.get(parts[0], 0)
        day = int(parts[1])
        h, m, s = map(int, parts[2].split(":"))
        return datetime.datetime(year, month, day, h, m, s, tzinfo=datetime.timezone.utc)
    except (IndexError, ValueError, KeyError):
        return None


def _fmt(dt: datetime.datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""


# ---------------------------------------------------------------------------
# Message pattern parsers
# ---------------------------------------------------------------------------

def _parse_message(msg: str, process: str) -> dict:
    """Extract structured fields from a log message. Returns partial row dict."""
    r: dict = {}

    # SSH: accepted login
    m = re.match(r"Accepted (\S+) for (\S+) from ([\d.a-fA-F:]+) port (\d+)", msg)
    if m:
        r["event_type"]   = "ssh_accepted"
        r["auth_method"]  = m.group(1)
        r["username"]     = m.group(2)
        r["source_ip"]    = m.group(3)
        r["source_port"]  = m.group(4)
        return r

    # SSH: failed password (invalid user)
    m = re.match(r"Failed \S+ for invalid user (\S+) from ([\d.a-fA-F:]+) port (\d+)", msg)
    if m:
        r["event_type"]  = "ssh_failed"
        r["username"]    = m.group(1)
        r["source_ip"]   = m.group(2)
        r["source_port"] = m.group(3)
        r["details"]     = "invalid user"
        return r

    # SSH: failed password (valid user)
    m = re.match(r"Failed \S+ for (\S+) from ([\d.a-fA-F:]+) port (\d+)", msg)
    if m:
        r["event_type"]  = "ssh_failed"
        r["username"]    = m.group(1)
        r["source_ip"]   = m.group(2)
        r["source_port"] = m.group(3)
        return r

    # SSH: invalid user attempt (before password)
    m = re.match(r"Invalid user (\S+) from ([\d.a-fA-F:]+) port (\d+)", msg)
    if m:
        r["event_type"]  = "ssh_invalid_user"
        r["username"]    = m.group(1)
        r["source_ip"]   = m.group(2)
        r["source_port"] = m.group(3)
        return r

    # SSH: disconnected
    m = re.match(r"Disconnected from user (\S+) ([\d.a-fA-F:]+) port (\d+)", msg)
    if m:
        r["event_type"]  = "ssh_disconnected"
        r["username"]    = m.group(1)
        r["source_ip"]   = m.group(2)
        r["source_port"] = m.group(3)
        return r

    # SSH: connection closed (preauth - failed)
    m = re.match(r"Connection closed by (?:invalid user |authenticating user )?(\S+) ([\d.a-fA-F:]+) port (\d+)", msg)
    if m:
        r["event_type"]  = "ssh_disconnected"
        r["username"]    = m.group(1)
        r["source_ip"]   = m.group(2)
        r["source_port"] = m.group(3)
        return r

    # sudo: command execution
    m = re.match(r"(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+)", msg)
    if m:
        r["event_type"]  = "sudo_command"
        r["username"]    = m.group(1)
        r["target_user"] = m.group(4)
        r["command"]     = m.group(5).strip()
        r["details"]     = f"TTY={m.group(2)} PWD={m.group(3)}"
        return r

    # su: switch user
    m = re.match(r"\(to (\S+)\) (\S+) on (\S+)", msg)
    if m:
        r["event_type"]  = "su_switch"
        r["target_user"] = m.group(1)
        r["username"]    = m.group(2)
        r["details"]     = f"tty={m.group(3)}"
        return r

    # PAM: session opened
    m = re.match(r"pam_unix\(([^:]+):session\): session opened for user (\S+)\(uid=\d+\) by (.+)", msg)
    if m:
        r["event_type"]  = "pam_session_open"
        r["process"]     = m.group(1)
        r["username"]    = m.group(2)
        r["details"]     = f"by={m.group(3).strip()}"
        return r

    # PAM: session closed
    m = re.match(r"pam_unix\(([^:]+):session\): session closed for user (\S+)", msg)
    if m:
        r["event_type"] = "pam_session_close"
        r["process"]    = m.group(1)
        r["username"]   = m.group(2)
        return r

    # PAM: authentication failure
    m = re.match(r"pam_unix\([^)]+\): authentication failure;(.+)", msg)
    if m:
        r["event_type"] = "pam_auth_failure"
        detail = m.group(1).strip()
        # extract user= and rhost= if present
        u = re.search(r"user=(\S+)", detail)
        h = re.search(r"rhost=([\d.a-fA-F:]+)", detail)
        if u:
            r["username"]  = u.group(1)
        if h:
            r["source_ip"] = h.group(1)
        r["details"] = detail
        return r

    # useradd: new user
    m = re.match(r"new user: name=(\S+), UID=(\d+), GID=(\d+), home=(\S+), shell=(\S+)", msg)
    if m:
        r["event_type"] = "useradd"
        r["username"]   = m.group(1)
        r["details"]    = f"UID={m.group(2)} GID={m.group(3)} home={m.group(4)} shell={m.group(5)}"
        return r

    # userdel
    m = re.match(r"delete user '(\S+)'", msg)
    if m:
        r["event_type"] = "userdel"
        r["username"]   = m.group(1)
        return r

    return {}


# ---------------------------------------------------------------------------
# Format detection and parsing
# ---------------------------------------------------------------------------

def _is_journald_json(path: str) -> bool:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            first = f.readline().strip()
        return first.startswith("{")
    except OSError:
        return False


def _parse_journald(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts_us = entry.get("__REALTIME_TIMESTAMP", "")
            dt = _filetime_us_to_dt(ts_us) if ts_us else None

            hostname = entry.get("_HOSTNAME", "")
            process  = entry.get("_COMM", entry.get("SYSLOG_IDENTIFIER", ""))
            pid      = entry.get("_PID", "")
            msg      = entry.get("MESSAGE", "")

            parsed = _parse_message(msg, process)
            if not parsed:
                continue

            row = {f: "" for f in FIELDNAMES}
            row["timestamp"]   = _fmt(dt)
            row["hostname"]    = hostname
            row["process"]     = process
            row["pid"]         = pid
            row["source_file"] = path
            row.update(parsed)
            rows.append(row)
    return rows


# Ubuntu auth.log: ISO 8601 timestamps
_ISO_LINE = re.compile(
    r"^(\S+)\s+(\S+)\s+([^\[]+?)(?:\[(\d+)\])?:\s+(.+)$"
)

# Traditional syslog: 'MMM DD HH:MM:SS hostname process[pid]: message'
_SYSLOG_LINE = re.compile(
    r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^\[]+?)(?:\[(\d+)\])?:\s+(.+)$"
)


def _parse_authlog(path: str) -> list[dict]:
    rows = []
    mtime_year = datetime.datetime.fromtimestamp(
        Path(path).stat().st_mtime, tz=datetime.timezone.utc
    ).year

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip()
            if not line:
                continue

            # Ubuntu auth.log: ISO 8601
            m = _ISO_LINE.match(line)
            if m:
                ts_str, hostname, process, pid, msg = m.groups()
                dt = _parse_iso_ts(ts_str)
            else:
                # Traditional syslog
                m = _SYSLOG_LINE.match(line)
                if not m:
                    continue
                ts_str, hostname, process, pid, msg = m.groups()
                dt = _parse_syslog_ts(ts_str, mtime_year)

            process = process.strip()
            parsed = _parse_message(msg.strip(), process)
            if not parsed:
                continue

            row = {f: "" for f in FIELDNAMES}
            row["timestamp"]   = _fmt(dt)
            row["hostname"]    = hostname
            row["process"]     = process
            row["pid"]         = pid or ""
            row["source_file"] = path
            row.update(parsed)
            rows.append(row)
    return rows


def parse_auth(path: str) -> list[dict]:
    if _is_journald_json(path):
        return _parse_journald(path)
    return _parse_authlog(path)


# ---------------------------------------------------------------------------
# Input collection
# ---------------------------------------------------------------------------

def _collect(inputs: list[str]) -> list[str]:
    paths = []
    for inp in inputs:
        p = Path(inp)
        if p.is_dir():
            for pattern in ("auth.log*", "secure*", "*.json"):
                paths.extend(str(x) for x in sorted(p.glob(pattern)))
        elif p.is_file():
            paths.append(str(p))
        else:
            paths.extend(sorted(glob.glob(inp, recursive=True)))
    return paths


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _summary(rows: list[dict]) -> None:
    from collections import Counter

    total = len(rows)
    hosts = {r["hostname"] for r in rows if r["hostname"]}
    event_counts = Counter(r["event_type"] for r in rows)

    accepted  = [r for r in rows if r["event_type"] == "ssh_accepted"]
    failed    = [r for r in rows if r["event_type"] == "ssh_failed"]
    invalid   = [r for r in rows if r["event_type"] == "ssh_invalid_user"]
    sudo_rows = [r for r in rows if r["event_type"] == "sudo_command"]
    useradds  = [r for r in rows if r["event_type"] == "useradd"]

    print(f"\nTotal events parsed:  {total}")
    print(f"Hosts:                {', '.join(sorted(hosts)) or 'unknown'}")

    print("\nEvent type breakdown:")
    for etype, count in event_counts.most_common():
        print(f"  {etype:<25} {count:>6}")

    if accepted:
        print(f"\nSSH accepted logins: {len(accepted)}")
        ips = Counter(r["source_ip"] for r in accepted)
        for ip, c in ips.most_common(5):
            print(f"  {ip:<20} {c} time(s)")

    if failed:
        print(f"\nSSH failed logins: {len(failed)}")
        ips = Counter(r["source_ip"] for r in failed)
        for ip, c in ips.most_common(5):
            print(f"  {ip:<20} {c} attempt(s)")

    if invalid:
        print(f"\nSSH invalid user attempts: {len(invalid)}")
        users = Counter(r["username"] for r in invalid)
        for u, c in users.most_common(5):
            print(f"  {u:<20} {c} attempt(s)")

    if sudo_rows:
        print(f"\nSudo commands: {len(sudo_rows)}")
        for r in sudo_rows[:10]:
            print(f"  [{r['timestamp']}] {r['username']} -> {r['target_user']}: {r['command'][:60]}")

    if useradds:
        print(f"\nUser accounts created: {len(useradds)}")
        for r in useradds:
            print(f"  [{r['timestamp']}] {r['username']} ({r['details']})")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="Parse Linux auth logs (auth.log, secure, journald JSON) into timeline CSV."
    )
    ap.add_argument("input", nargs="+", help="Log file(s), journald JSON export(s), or directory")
    ap.add_argument("-o", "--output", default="-", help="Output CSV (default: stdout)")
    ap.add_argument("--summary", action="store_true", help="Print triage summary")
    args = ap.parse_args()

    paths = _collect(args.input)
    if not paths:
        print("No files found.", file=sys.stderr)
        sys.exit(1)

    all_rows = []
    errors = 0
    for p in paths:
        try:
            rows = parse_auth(p)
            all_rows.extend(rows)
        except Exception as e:
            print(f"Warning: could not parse {p}: {e}", file=sys.stderr)
            errors += 1

    if args.output == "-":
        w = csv.DictWriter(sys.stdout, fieldnames=FIELDNAMES, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(all_rows)
    else:
        with open(args.output, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=FIELDNAMES, extrasaction="ignore", lineterminator="\n")
            w.writeheader()
            w.writerows(all_rows)
        print(f"Wrote {len(all_rows)} rows to {args.output}", file=sys.stderr)

    if errors:
        print(f"Warning: {errors} file(s) failed.", file=sys.stderr)

    if args.summary:
        _summary(all_rows)


if __name__ == "__main__":
    main()
