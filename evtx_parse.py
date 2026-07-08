#!/usr/bin/env python3
"""
evtx-parse: Windows Event Log parser for Linux
Parses .evtx files and outputs structured CSV.
"""

import argparse
import csv
import json
import sys
import glob
import collections
from pathlib import Path

try:
    import Evtx.Evtx as evtx_lib
except ImportError:
    print("[!] python-evtx not installed. Run: pip install python-evtx", file=sys.stderr)
    sys.exit(1)

try:
    import xmltodict
except ImportError:
    print("[!] xmltodict not installed. Run: pip install xmltodict", file=sys.stderr)
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("[!] PyYAML not installed. Run: pip install PyYAML", file=sys.stderr)
    sys.exit(1)


FIELDNAMES = [
    "timestamp_utc",
    "record_id",
    "event_id",
    "level",
    "channel",
    "provider",
    "computer",
    "user_sid",
    "process_id",
    "thread_id",
    "description",
    "event_data",
    "source_file",
]

LEVEL_NAMES = {
    "0": "Information",
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information",
    "5": "Verbose",
}


WATCHLIST = {
    "1102":  ("CRITICAL", "Audit log cleared"),
    "104":   ("CRITICAL", "Event log cleared"),
    "7045":  ("HIGH",     "New service installed"),
    "4719":  ("HIGH",     "Audit policy changed"),
    "4720":  ("HIGH",     "User account created"),
    "4726":  ("HIGH",     "User account deleted"),
    "5001":  ("HIGH",     "Windows Defender real-time protection disabled"),
    "4698":  ("HIGH",     "Scheduled task created"),
    "4702":  ("MEDIUM",   "Scheduled task updated"),
    "4648":  ("MEDIUM",   "Logon with explicit credentials (runas)"),
    "4728":  ("MEDIUM",   "Member added to global security group"),
    "4732":  ("MEDIUM",   "Member added to local security group"),
    "4756":  ("MEDIUM",   "Member added to universal security group"),
    "4740":  ("MEDIUM",   "Account lockout"),
    "5861":  ("HIGH",     "WMI permanent event subscription registered"),
    "4104":  ("MEDIUM",   "PowerShell script block logged"),
}

WATCHLIST_THRESHOLD = {
    "4625": ("HIGH", "Failed logon", 50),
    "4771": ("HIGH", "Kerberos pre-auth failed", 20),
}


class Stats:
    def __init__(self):
        self.total = 0
        self.event_ids = collections.Counter()
        self.computers = collections.Counter()
        self.channels = collections.Counter()
        self.first_ts = None
        self.last_ts = None
        self.watchlist_hits = collections.Counter()
        self.ps_warning_count = 0

    # Watchlist entries that require a specific provider to avoid EID collisions.
    WATCHLIST_PROVIDER = {
        ("microsoft-windows-eventlog",          "104"):  ("104",  "CRITICAL", "Event log cleared"),
        ("microsoft-windows-security-auditing", "1102"): ("1102", "CRITICAL", "Audit log cleared"),
    }

    def update(self, row: dict):
        self.total += 1
        eid = row["event_id"]
        self.event_ids[eid] += 1
        self.computers[row["computer"]] += 1
        self.channels[row["channel"]] += 1

        ts = row["timestamp_utc"]
        if ts:
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts

        provider = row.get("provider", "").lower()
        provider_key = (provider, eid)
        if provider_key in self.WATCHLIST_PROVIDER:
            canonical_eid = self.WATCHLIST_PROVIDER[provider_key][0]
            self.watchlist_hits[canonical_eid] += 1
        elif eid in WATCHLIST and eid not in ("104", "1102"):
            self.watchlist_hits[eid] += 1

        if eid == "4104":
            ed = row.get("event_data", "")
            if ed:
                try:
                    d = json.loads(ed)
                    script = (d.get("ScriptBlockText") or "").lower()
                    if any(kw in script for kw in (
                        "invoke-mimikatz", "invoke-expression", "iex(", "iex ",
                        "downloadstring", "downloadfile", "net.webclient",
                        "encodedcommand", "-enc ", "frombase64string",
                        "bypass", "amsiutils", "reflection.assembly",
                        "shellcode", "virtualalloc",
                    )):
                        self.ps_warning_count += 1
                except Exception:
                    pass


def _label(severity: str) -> str:
    return {"CRITICAL": "[!!!]", "HIGH": "[!]", "MEDIUM": "[~]"}.get(severity, "[ ]")


def print_summary(stats: Stats, maps: dict, parse_errors: int):
    err = sys.stderr
    W = 60
    print("\n" + "=" * W, file=err)
    print("  TRIAGE SUMMARY", file=err)
    print("=" * W, file=err)

    print(f"\n  Records parsed : {stats.total:,}", file=err)
    if parse_errors:
        print(f"  Parse errors   : {parse_errors}", file=err)
    print(f"  Date range     : {(stats.first_ts or 'unknown')[:19]} UTC", file=err)
    print(f"               to: {(stats.last_ts or 'unknown')[:19]} UTC", file=err)

    print(f"\n  Computers ({len(stats.computers)}):", file=err)
    for host, count in stats.computers.most_common(10):
        print(f"    {host}  ({count:,} events)", file=err)

    print(f"\n  Channels ({len(stats.channels)}):", file=err)
    for ch, count in stats.channels.most_common():
        print(f"    {ch}  ({count:,})", file=err)

    print(f"\n  Top event IDs:", file=err)
    for eid, count in stats.event_ids.most_common(15):
        key = next((k for k in maps if k[1] == eid), None)
        desc = maps[key] if key else ""
        line = f"    {eid:<8} {count:>8,}"
        if desc:
            line += f"  {desc}"
        print(line, file=err)

    print(f"\n  Watchlist:", file=err)
    any_hit = False

    for eid, (sev, label) in WATCHLIST.items():
        count = stats.watchlist_hits.get(eid, 0)
        if count:
            print(f"    {_label(sev)} {label} (EID {eid}): {count:,}", file=err)
            any_hit = True

    for eid, (sev, label, threshold) in WATCHLIST_THRESHOLD.items():
        count = stats.event_ids.get(eid, 0)
        if count >= threshold:
            print(f"    {_label(sev)} {label} (EID {eid}): {count:,} (threshold: {threshold})", file=err)
            any_hit = True

    if stats.ps_warning_count:
        print(f"    [!!!] PowerShell script blocks with suspicious keywords: {stats.ps_warning_count}", file=err)
        any_hit = True

    if not any_hit:
        print("    No watchlist events detected.", file=err)

    print("\n" + "=" * W + "\n", file=err)


def load_maps(maps_dir: Path) -> dict:
    maps = {}
    if not maps_dir.exists():
        return maps
    for f in maps_dir.glob("*.yaml"):
        try:
            with open(f) as fh:
                data = yaml.safe_load(fh)
            if not data:
                continue
            for entry in data.get("events", []):
                provider = entry.get("provider", "").lower()
                event_id = str(entry.get("event_id", ""))
                desc = entry.get("description", "")
                maps[(provider, event_id)] = desc
        except Exception as e:
            print(f"[!] Failed to load map {f}: {e}", file=sys.stderr)
    return maps


def safe_get(d, *keys, default=""):
    for key in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(key, default)
    return d if d is not None else default


def extract_event_data(event_data_raw) -> dict:
    result = {}
    if not isinstance(event_data_raw, dict):
        return result
    items = event_data_raw.get("Data", [])
    if isinstance(items, dict):
        items = [items]
    elif not isinstance(items, list):
        if items:
            result["Data"] = str(items)
        return result
    for item in items:
        if isinstance(item, dict):
            name = item.get("@Name") or item.get("@name", "")
            value = item.get("#text", "")
            if name:
                result[name] = value if value is not None else ""
        elif isinstance(item, str) and item.strip():
            result.setdefault("_data", []).append(item)
    if "_data" in result:
        result["_data"] = "|".join(result["_data"])
    return result


def parse_record(record, maps: dict, source_file: str) -> dict | None:
    try:
        xml_str = record.xml()
        d = xmltodict.parse(xml_str)
        event = d.get("Event", {})
        sys_block = event.get("System", {})

        provider_raw = sys_block.get("Provider", {})
        if isinstance(provider_raw, dict):
            provider_name = (
                provider_raw.get("@Name")
                or provider_raw.get("@EventSourceName", "")
            )
        else:
            provider_name = str(provider_raw) if provider_raw else ""

        time_raw = sys_block.get("TimeCreated", {})
        timestamp = safe_get(time_raw, "@SystemTime") if isinstance(time_raw, dict) else ""

        event_id_raw = sys_block.get("EventID", "")
        if isinstance(event_id_raw, dict):
            event_id = str(event_id_raw.get("#text", ""))
        else:
            event_id = str(event_id_raw)

        level_raw = str(sys_block.get("Level", "0"))
        level = LEVEL_NAMES.get(level_raw, level_raw)

        channel = str(sys_block.get("Channel", ""))
        computer = str(sys_block.get("Computer", ""))

        exec_raw = sys_block.get("Execution", {})
        if isinstance(exec_raw, dict):
            process_id = str(exec_raw.get("@ProcessID", ""))
            thread_id = str(exec_raw.get("@ThreadID", ""))
        else:
            process_id = thread_id = ""

        sec_raw = sys_block.get("Security", {})
        user_sid = safe_get(sec_raw, "@UserID") if isinstance(sec_raw, dict) else ""

        record_id = str(sys_block.get("EventRecordID", ""))

        event_data_raw = event.get("EventData") or event.get("UserData", {})
        event_data = extract_event_data(event_data_raw)

        key = (provider_name.lower(), event_id)
        description = maps.get(key, "")

        return {
            "timestamp_utc": timestamp,
            "record_id": record_id,
            "event_id": event_id,
            "level": level,
            "channel": channel,
            "provider": provider_name,
            "computer": computer,
            "user_sid": user_sid,
            "process_id": process_id,
            "thread_id": thread_id,
            "description": description,
            "event_data": json.dumps(event_data, ensure_ascii=False) if event_data else "",
            "source_file": source_file,
        }
    except Exception as e:
        return None


def parse_file(evtx_path: Path, maps: dict, writer, id_filter, channel_filter, stats: Stats | None = None) -> tuple[int, int]:
    parsed = 0
    errors = 0
    try:
        with evtx_lib.Evtx(str(evtx_path)) as log:
            for record in log.records():
                row = parse_record(record, maps, evtx_path.name)
                if row is None:
                    errors += 1
                    continue
                if stats:
                    stats.update(row)
                if id_filter and row["event_id"] not in id_filter:
                    continue
                if channel_filter and row["channel"].lower() not in channel_filter:
                    continue
                try:
                    writer.writerow(row)
                    parsed += 1
                except Exception:
                    errors += 1
    except Exception as e:
        print(f"[!] Failed to open {evtx_path}: {e}", file=sys.stderr)
        errors += 1
    return parsed, errors


def collect_files(inputs: list) -> list:
    seen = set()
    files = []
    for inp in inputs:
        p = Path(inp)
        if p.is_file() and p.suffix.lower() == ".evtx":
            if p not in seen:
                seen.add(p)
                files.append(p)
        elif p.is_dir():
            for match in sorted(p.rglob("*")):
                if match.suffix.lower() == ".evtx" and match not in seen:
                    seen.add(match)
                    files.append(match)
        else:
            for match in sorted(glob.glob(inp, recursive=True)):
                mp = Path(match)
                if mp.suffix.lower() == ".evtx" and mp not in seen:
                    seen.add(mp)
                    files.append(mp)
    return files


def main():
    ap = argparse.ArgumentParser(
        prog="evtx-parse",
        description="Windows Event Log parser for Linux. Outputs structured CSV.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s Security.evtx -o security.csv
  %(prog)s /mnt/evidence/Windows/System32/winevt/Logs/ -o all_events.csv
  %(prog)s /mnt/evidence/ --filter-id 4624,4625,4648 -o logons.csv
  %(prog)s /mnt/evidence/ --filter-channel Security,System -o filtered.csv
  %(prog)s /mnt/evidence/ --filter-id 1 --maps-dir ./maps -o sysmon.csv

For E01 images, mount first:
  ewfmount image.E01 /mnt/ewf && mount -r /mnt/ewf/ewf1 /mnt/image
  then point %(prog)s at /mnt/image/Windows/System32/winevt/Logs/
        """,
    )
    ap.add_argument("input", nargs="+", help="EVTX file, directory, or glob pattern")
    ap.add_argument("-o", "--output", default="-", metavar="FILE", help="Output CSV (default: stdout)")
    ap.add_argument("--maps-dir", default=None, metavar="DIR", help="Event map YAML directory (default: maps/ next to script)")
    ap.add_argument("--filter-id", default=None, metavar="IDS", help="Comma-separated Event IDs to include")
    ap.add_argument("--filter-channel", default=None, metavar="CHANNELS", help="Comma-separated channels to include (case-insensitive)")
    ap.add_argument("--no-header", action="store_true", help="Suppress CSV header row")
    ap.add_argument("--summary", "-s", action="store_true", help="Print triage summary after parsing")
    ap.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")
    args = ap.parse_args()

    maps_dir = Path(args.maps_dir) if args.maps_dir else Path(__file__).parent / "maps"
    maps = load_maps(maps_dir)
    if not args.quiet:
        print(f"[*] Maps loaded: {len(maps)} event descriptions", file=sys.stderr)

    files = collect_files(args.input)
    if not files:
        print("[!] No .evtx files found in the provided path(s).", file=sys.stderr)
        sys.exit(1)
    if not args.quiet:
        print(f"[*] Files to parse: {len(files)}", file=sys.stderr)

    id_filter = set(args.filter_id.split(",")) if args.filter_id else None
    channel_filter = {c.lower() for c in args.filter_channel.split(",")} if args.filter_channel else None

    total_parsed = 0
    total_errors = 0
    stats = Stats() if args.summary else None

    if args.output == "-":
        out_fh = sys.stdout
        close_fh = False
    else:
        out_fh = open(args.output, "w", newline="", encoding="utf-8")
        close_fh = True

    try:
        writer = csv.DictWriter(out_fh, fieldnames=FIELDNAMES, extrasaction="ignore")
        if not args.no_header:
            writer.writeheader()
        for f in files:
            if not args.quiet:
                print(f"[*] Parsing: {f}", file=sys.stderr)
            p, e = parse_file(f, maps, writer, id_filter, channel_filter, stats)
            total_parsed += p
            total_errors += e
    finally:
        if close_fh:
            out_fh.close()

    if not args.quiet:
        print(f"[+] Complete. Records written: {total_parsed}, parse errors: {total_errors}", file=sys.stderr)

    if stats:
        print_summary(stats, maps, total_errors)


if __name__ == "__main__":
    main()
