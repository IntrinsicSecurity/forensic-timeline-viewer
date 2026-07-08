#!/usr/bin/env python3
"""
usn-parse: Windows USN Journal ($J) parser for Linux
Parses $Extend/$J files and outputs structured CSV.

Timestamps: all times are UTC.
The USN journal records file system changes (create, delete, rename, write, etc.)
Use alongside mft_parse.py output for a combined file activity timeline.
"""

import argparse
import csv
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path


FIELDNAMES = [
    "timestamp_utc",
    "usn",
    "filename",
    "extension",
    "file_ref",
    "file_seq",
    "parent_ref",
    "parent_seq",
    "reason",
    "file_attributes",
    "source_file",
]

# USN_REASON flags (from winioctl.h)
USN_REASONS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x00400000: "TRANSACTED_CHANGE",
    0x80000000: "CLOSE",
}

FILE_ATTRS = {
    0x00000001: "READONLY",
    0x00000002: "HIDDEN",
    0x00000004: "SYSTEM",
    0x00000010: "DIRECTORY",
    0x00000020: "ARCHIVE",
    0x00000040: "DEVICE",
    0x00000080: "NORMAL",
    0x00000100: "TEMPORARY",
    0x00000200: "SPARSE_FILE",
    0x00000400: "REPARSE_POINT",
    0x00000800: "COMPRESSED",
    0x00001000: "OFFLINE",
    0x00002000: "NOT_CONTENT_INDEXED",
    0x00004000: "ENCRYPTED",
}

# Minimum valid record length for V2
MIN_RECORD_LEN = 60
BLOCK_SIZE = 0x10000  # 64KB - scan in blocks when seeking past sparse area


def filetime_to_dt(ft: int) -> str:
    """Convert Windows FILETIME (100ns intervals since 1601-01-01) to UTC string."""
    if ft == 0:
        return ""
    try:
        ts = datetime(1601, 1, 1, tzinfo=timezone.utc).timestamp() + ft / 1e7
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    except Exception:
        return ""


def decode_reason(reason: int) -> str:
    return "|".join(name for flag, name in USN_REASONS.items() if reason & flag)


def decode_attrs(attrs: int) -> str:
    return "|".join(name for flag, name in FILE_ATTRS.items() if attrs & flag)


def parse_file_ref(ref: int) -> tuple[int, int]:
    """Split 8-byte file reference into (entry_number, sequence_number)."""
    entry = ref & 0x0000FFFFFFFFFFFF
    seq = (ref >> 48) & 0xFFFF
    return entry, seq


def find_first_record(data: bytes) -> int:
    """Find offset of first valid USN_RECORD_V2 in data, skipping sparse zeros."""
    offset = 0
    length = len(data)
    while offset < length - MIN_RECORD_LEN:
        if data[offset:offset + 4] == b'\x00\x00\x00\x00':
            # Skip to next block boundary
            next_block = ((offset // BLOCK_SIZE) + 1) * BLOCK_SIZE
            offset = next_block
            continue
        rec_len = struct.unpack_from("<I", data, offset)[0]
        major = struct.unpack_from("<H", data, offset + 4)[0]
        if rec_len >= MIN_RECORD_LEN and major == 2:
            return offset
        offset += 8
    return -1


def parse_record(data: bytes, offset: int, source_file: str) -> tuple[dict | None, int]:
    """Parse one USN_RECORD_V2. Returns (row, next_offset) or (None, next_offset)."""
    if offset + MIN_RECORD_LEN > len(data):
        return None, len(data)

    try:
        rec_len = struct.unpack_from("<I", data, offset)[0]
        major   = struct.unpack_from("<H", data, offset + 4)[0]

        if rec_len < MIN_RECORD_LEN or major != 2:
            return None, offset + 8

        if offset + rec_len > len(data):
            return None, len(data)

        file_ref_raw    = struct.unpack_from("<Q", data, offset + 8)[0]
        parent_ref_raw  = struct.unpack_from("<Q", data, offset + 16)[0]
        usn             = struct.unpack_from("<q", data, offset + 24)[0]
        filetime        = struct.unpack_from("<Q", data, offset + 32)[0]
        reason          = struct.unpack_from("<I", data, offset + 40)[0]
        # source_info   = struct.unpack_from("<I", data, offset + 44)[0]  # not used
        # security_id   = struct.unpack_from("<I", data, offset + 48)[0]  # not used
        file_attrs      = struct.unpack_from("<I", data, offset + 52)[0]
        fname_len       = struct.unpack_from("<H", data, offset + 56)[0]
        fname_off       = struct.unpack_from("<H", data, offset + 58)[0]

        fname_start = offset + fname_off
        fname_end   = fname_start + fname_len
        if fname_end > offset + rec_len:
            return None, offset + rec_len

        filename = data[fname_start:fname_end].decode("utf-16-le", errors="replace")
        extension = Path(filename).suffix.lstrip(".").lower() if filename else ""

        file_ref, file_seq     = parse_file_ref(file_ref_raw)
        parent_ref, parent_seq = parse_file_ref(parent_ref_raw)

        row = {
            "timestamp_utc":  filetime_to_dt(filetime),
            "usn":            usn,
            "filename":       filename,
            "extension":      extension,
            "file_ref":       file_ref,
            "file_seq":       file_seq,
            "parent_ref":     parent_ref,
            "parent_seq":     parent_seq,
            "reason":         decode_reason(reason),
            "file_attributes": decode_attrs(file_attrs),
            "source_file":    source_file,
        }
        return row, offset + rec_len

    except Exception:
        return None, offset + 8


def print_summary(total: int, errors: int, date_range: tuple,
                  reasons: dict, extensions: dict):
    err = sys.stderr
    W = 60
    print("\n" + "=" * W, file=err)
    print("  USN JOURNAL TRIAGE SUMMARY", file=err)
    print("=" * W, file=err)
    print(f"\n  Total records    : {total:,}", file=err)
    print(f"  Parse errors     : {errors:,}", file=err)
    if date_range[0] and date_range[1]:
        print(f"\n  Date range: {date_range[0][:19]} UTC", file=err)
        print(f"          to: {date_range[1][:19]} UTC", file=err)

    print(f"\n  Top reason flags:", file=err)
    for reason, count in sorted(reasons.items(), key=lambda x: -x[1])[:15]:
        print(f"    {reason:<35} {count:>8,}", file=err)

    print(f"\n  Top file extensions:", file=err)
    for ext, count in sorted(extensions.items(), key=lambda x: -x[1])[:15]:
        label = ext if ext else "(no extension)"
        print(f"    {label:<25} {count:>8,}", file=err)

    print("\n" + "=" * W + "\n", file=err)


def main():
    ap = argparse.ArgumentParser(
        prog="usn-parse",
        description="Windows USN Journal ($J) parser for Linux. Outputs structured CSV.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s '$J' -o usn.csv
  %(prog)s '$J' -o usn.csv --summary
  %(prog)s '$J' -o usn.csv --filter-ext exe,dll,ps1,bat
  %(prog)s '$J' -o usn.csv --filter-reason FILE_CREATE,FILE_DELETE

For KAPE collections:
  %(prog)s '/path/to/kape/C/$Extend/$J' -o usn.csv --summary

For E01 images, mount first:
  ewfmount image.E01 /mnt/ewf && mount -r /mnt/ewf/ewf1 /mnt/image
  then point %(prog)s at /mnt/image/$Extend/$J
        """,
    )
    ap.add_argument("input", help="$J file path")
    ap.add_argument("-o", "--output", default="-", metavar="FILE", help="Output CSV (default: stdout)")
    ap.add_argument("--summary", "-s", action="store_true", help="Print triage summary after parsing")
    ap.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")
    ap.add_argument("--filter-ext", default=None, metavar="EXTS",
                    help="Comma-separated extensions to include (e.g. exe,dll,ps1)")
    ap.add_argument("--filter-reason", default=None, metavar="REASONS",
                    help="Comma-separated reason flags to include (e.g. FILE_CREATE,FILE_DELETE)")
    ap.add_argument("--no-header", action="store_true", help="Suppress CSV header row")
    args = ap.parse_args()

    j_path = Path(args.input)
    if not j_path.exists():
        print(f"[!] File not found: {j_path}", file=sys.stderr)
        sys.exit(1)

    ext_filter    = {e.lower().lstrip(".") for e in args.filter_ext.split(",")} if args.filter_ext else None
    reason_filter = {r.upper() for r in args.filter_reason.split(",")} if args.filter_reason else None

    if not args.quiet:
        print(f"[*] Reading {j_path} ({j_path.stat().st_size / 1024 / 1024:.1f} MB)…", file=sys.stderr)

    data = j_path.read_bytes()

    offset = find_first_record(data)
    if offset < 0:
        print("[!] No valid USN records found.", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"[*] First record at offset {offset:#x}", file=sys.stderr)

    total = errors = 0
    first_ts = last_ts = ""
    reasons: dict[str, int] = {}
    extensions: dict[str, int] = {}

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

        while offset < len(data):
            # Skip sparse zero blocks
            if data[offset:offset + 4] == b'\x00\x00\x00\x00':
                next_block = ((offset // BLOCK_SIZE) + 1) * BLOCK_SIZE
                offset = next_block
                continue

            row, offset = parse_record(data, offset, j_path.name)
            if row is None:
                errors += 1
                continue

            total += 1
            ts = row["timestamp_utc"]
            if ts:
                if not first_ts or ts < first_ts:
                    first_ts = ts
                if not last_ts or ts > last_ts:
                    last_ts = ts

            for flag in row["reason"].split("|"):
                if flag:
                    reasons[flag] = reasons.get(flag, 0) + 1

            ext = row["extension"]
            extensions[ext] = extensions.get(ext, 0) + 1

            # Apply filters
            if ext_filter and row["extension"] not in ext_filter:
                continue
            if reason_filter:
                record_reasons = set(row["reason"].split("|"))
                if not record_reasons & reason_filter:
                    continue

            try:
                writer.writerow(row)
            except Exception:
                errors += 1

        if not args.quiet:
            print(f"[+] Complete. Records parsed: {total:,}, errors: {errors}", file=sys.stderr)

        if args.summary:
            print_summary(total, errors, (first_ts, last_ts), reasons, extensions)

    finally:
        if close_fh:
            out_fh.close()


if __name__ == "__main__":
    main()
