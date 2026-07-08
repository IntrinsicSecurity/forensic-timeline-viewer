#!/usr/bin/env python3
"""
recyclebin_parse.py - Parse Windows Recycle Bin $I metadata files.

Accepts a single $I file or a directory (recurses into SID subfolders).
Outputs structured CSV compatible with the Intrinsic Timeline Viewer.

Usage:
    python3 recyclebin_parse.py /kape/C/$Recycle.Bin/ -o recyclebin.csv
    python3 recyclebin_parse.py /kape/C/$Recycle.Bin/$I_abc123 -o recyclebin.csv --summary
"""

import argparse
import csv
import os
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path


_FILETIME_EPOCH_DELTA = 116_444_736_000_000_000  # 100ns intervals between 1601-01-01 and 1970-01-01
_VERSION1_HEADER = 28       # version 1: size(8) + ts(8) + size_field(4) + path (fixed 520 bytes)
_VERSION2_HEADER_MIN = 28   # version 2: size(8) + ts(8) + path_len(4) + path (variable)


def _filetime_to_utc(filetime: int) -> str:
    if filetime == 0:
        return ""
    try:
        unix_us = (filetime - _FILETIME_EPOCH_DELTA) // 10
        dt = datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return ""


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024


def parse_i_file(path: Path) -> dict | None:
    try:
        data = path.read_bytes()
    except OSError as e:
        print(f"[!] Cannot read {path}: {e}", file=sys.stderr)
        return None

    if len(data) < 24:
        return None

    version = struct.unpack_from("<q", data, 0)[0]
    file_size = struct.unpack_from("<q", data, 8)[0]
    filetime = struct.unpack_from("<q", data, 16)[0]

    original_path = ""
    if version == 1:
        # Version 1: fixed 260-char (520-byte) UTF-16LE path at offset 28
        if len(data) >= 28 + 520:
            raw = data[28:28 + 520]
            try:
                original_path = raw.decode("utf-16-le").rstrip("\x00")
            except UnicodeDecodeError:
                original_path = ""
    elif version == 2:
        # Version 2: 4-byte path length (chars) at offset 24, then UTF-16LE path
        if len(data) >= 28:
            path_len = struct.unpack_from("<i", data, 24)[0]
            byte_len = path_len * 2
            if len(data) >= 28 + byte_len and path_len > 0:
                raw = data[28:28 + byte_len]
                try:
                    original_path = raw.decode("utf-16-le").rstrip("\x00")
                except UnicodeDecodeError:
                    original_path = ""
    else:
        return None

    filename = Path(original_path).name if original_path else ""
    extension = Path(original_path).suffix.lstrip(".").lower() if original_path else ""

    return {
        "timestamp_utc": _filetime_to_utc(filetime),
        "original_path": original_path,
        "filename": filename,
        "extension": extension,
        "size_bytes": file_size,
        "size_human": _human_size(file_size) if file_size >= 0 else "",
        "recycle_bin_file": path.name,
        "source_dir": str(path.parent),
    }


def collect_i_files(target: Path) -> list[Path]:
    if target.is_file():
        if target.name.upper().startswith("$I"):
            return [target]
        print(f"[!] {target.name} does not look like a $I file.", file=sys.stderr)
        return []

    found = []
    for root, dirs, files in os.walk(target):
        for f in files:
            if f.upper().startswith("$I"):
                found.append(Path(root) / f)
    return sorted(found)


def print_summary(records: list[dict], source: str):
    print(f"\n=== Recycle Bin Summary: {source} ===")
    print(f"Total deleted items : {len(records)}")

    if not records:
        return

    dated = [r for r in records if r["timestamp_utc"]]
    if dated:
        timestamps = sorted(r["timestamp_utc"] for r in dated)
        print(f"Earliest deletion   : {timestamps[0]}")
        print(f"Latest deletion     : {timestamps[-1]}")

    total_bytes = sum(r["size_bytes"] for r in records if isinstance(r["size_bytes"], int) and r["size_bytes"] > 0)
    print(f"Total original size : {_human_size(total_bytes)}")

    from collections import Counter
    exts = Counter(r["extension"] for r in records if r["extension"])
    if exts:
        print("\nTop extensions:")
        for ext, count in exts.most_common(10):
            print(f"  .{ext:<15} {count}")

    sid_dirs = Counter(r["source_dir"] for r in records)
    if len(sid_dirs) > 1:
        print("\nBy SID folder:")
        for sid_dir, count in sid_dirs.most_common():
            print(f"  {sid_dir}  ({count} items)")


_FIELDNAMES = [
    "timestamp_utc", "original_path", "filename", "extension",
    "size_bytes", "size_human", "recycle_bin_file", "source_dir",
]


def main():
    ap = argparse.ArgumentParser(
        prog="recyclebin_parse",
        description="Parse Windows Recycle Bin $I metadata files.",
    )
    ap.add_argument("target", help="$I file or directory containing $I files (e.g. C\\$Recycle.Bin\\)")
    ap.add_argument("-o", "--output", required=True, help="Output CSV path")
    ap.add_argument("--summary", action="store_true", help="Print a triage summary after parsing")
    args = ap.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"[!] Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    i_files = collect_i_files(target)
    if not i_files:
        print("[!] No $I files found.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Found {len(i_files)} $I file(s). Parsing...")

    records = []
    errors = 0
    for f in i_files:
        rec = parse_i_file(f)
        if rec:
            records.append(rec)
        else:
            errors += 1

    records.sort(key=lambda r: r["timestamp_utc"] or "")

    out = Path(args.output)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_FIELDNAMES)
        writer.writeheader()
        writer.writerows(records)

    print(f"[+] Written {len(records)} records to {out}")
    if errors:
        print(f"[!] {errors} file(s) could not be parsed (unrecognised format or read error).")

    if args.summary:
        print_summary(records, str(target))


if __name__ == "__main__":
    main()
