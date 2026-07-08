#!/usr/bin/env python3
"""
mft-parse: Windows MFT ($MFT) parser for Linux
Parses $MFT files and outputs structured CSV.

Timestamps: all times are UTC as stored in the MFT.
Two timestamp sets are included per entry:
  - si_* : $STANDARD_INFORMATION (0x10) - displayed by Windows Explorer, can be timestomped
  - fn_* : $FILE_NAME (0x30) - harder to modify, useful for timestomp detection
"""

import argparse
import csv
import sys
from pathlib import Path

try:
    from mft import PyMftParser, PyMftAttributeX10, PyMftAttributeX30
except ImportError:
    print("[!] mft not installed. Run: pip install mft", file=sys.stderr)
    sys.exit(1)


FIELDNAMES = [
    "entry_id",
    "sequence",
    "full_path",
    "filename",
    "extension",
    "file_size",
    "allocated",
    "is_directory",
    "is_deleted",
    "hard_link_count",
    "si_created",
    "si_modified",
    "si_accessed",
    "si_mft_modified",
    "fn_created",
    "fn_modified",
    "fn_accessed",
    "fn_mft_modified",
    "si_fn_discrepancy",
    "si_fn_direction",
    "file_attributes",
    "source_file",
]


def fmt_ts(ts) -> str:
    if ts is None:
        return ""
    return str(ts).replace("+00:00", "")


def ts_diff(si_ts, fn_ts):
    """Return (has_discrepancy, direction) for SI vs FN timestamp pair.
    direction: 'SI<FN' means SI appears older (common after rebuild/migration or backdating),
               'SI>FN' means SI appears newer (unusual - FN cannot normally be older than SI created).
    """
    if si_ts is None or fn_ts is None:
        return False, ""
    try:
        delta = (si_ts - fn_ts).total_seconds()
        if abs(delta) <= 1:
            return False, ""
        return True, "SI<FN" if delta < 0 else "SI>FN"
    except Exception:
        return False, ""


def parse_entry(entry, source_file: str) -> dict | None:
    try:
        si = None
        fn = None

        for attr in entry.attributes():
            content = attr.attribute_content
            if content is None:
                continue
            t = type(content).__name__
            if t == "PyMftAttributeX10" and si is None:
                si = content
            elif t == "PyMftAttributeX30" and fn is None:
                fn = content

        flags = str(entry.flags)
        is_allocated = "ALLOCATED" in flags
        is_deleted = not is_allocated

        fn_flags = str(fn.flags) if fn else ""
        is_directory = (
            "INDEX_PRESENT" in flags
            or "FILE_ATTRIBUTE_IS_DIRECTORY" in fn_flags
        )

        full_path = entry.full_path or ""
        filename = Path(full_path).name if full_path else ""
        extension = Path(filename).suffix.lstrip(".").lower() if filename and not is_directory else ""

        si_created      = si.created      if si else None
        si_modified     = si.modified     if si else None
        si_accessed     = si.accessed     if si else None
        si_mft_modified = si.mft_modified if si else None

        fn_created      = fn.created      if fn else None
        fn_modified     = fn.modified     if fn else None
        fn_accessed     = fn.accessed     if fn else None
        fn_mft_modified = fn.mft_modified if fn else None

        disc_results = [
            ts_diff(si_created,      fn_created),
            ts_diff(si_modified,     fn_modified),
            ts_diff(si_accessed,     fn_accessed),
            ts_diff(si_mft_modified, fn_mft_modified),
        ]
        discrepancy = any(d for d, _ in disc_results)
        directions = list({dr for _, dr in disc_results if dr})
        direction = ",".join(sorted(directions))

        return {
            "entry_id":          entry.entry_id,
            "sequence":          entry.sequence,
            "full_path":         full_path,
            "filename":          filename,
            "extension":         extension,
            "file_size":         entry.file_size or 0,
            "allocated":         "Yes" if is_allocated else "No",
            "is_directory":      "Yes" if is_directory else "No",
            "is_deleted":        "Yes" if is_deleted else "No",
            "hard_link_count":   entry.hard_link_count or 0,
            "si_created":        fmt_ts(si_created),
            "si_modified":       fmt_ts(si_modified),
            "si_accessed":       fmt_ts(si_accessed),
            "si_mft_modified":   fmt_ts(si_mft_modified),
            "fn_created":        fmt_ts(fn_created),
            "fn_modified":       fmt_ts(fn_modified),
            "fn_accessed":       fmt_ts(fn_accessed),
            "fn_mft_modified":   fmt_ts(fn_mft_modified),
            "si_fn_discrepancy": "Yes" if discrepancy else "No",
            "si_fn_direction":   direction,
            "file_attributes":   fn_flags if fn_flags else flags,
            "source_file":       source_file,
        }
    except Exception:
        return None


def print_summary(total: int, errors: int, deleted: int, dirs: int,
                  discrepancies: int, disc_si_older: int, disc_si_newer: int,
                  extensions: dict, date_range: tuple):
    err = sys.stderr
    W = 60
    print("\n" + "=" * W, file=err)
    print("  MFT TRIAGE SUMMARY", file=err)
    print("=" * W, file=err)
    print(f"\n  Total entries    : {total:,}", file=err)
    print(f"  Parse errors     : {errors:,}", file=err)
    print(f"  Directories      : {dirs:,}", file=err)
    print(f"  Deleted entries  : {deleted:,}", file=err)
    print(f"  SI/FN timestamp discrepancies: {discrepancies:,}", file=err)
    if discrepancies:
        print(f"    SI older than FN (SI<FN): {disc_si_older:,}  (common after rebuild/migration)", file=err)
        print(f"    SI newer than FN (SI>FN): {disc_si_newer:,}  (small deltas normal in WinSxS; large deltas warrant investigation)", file=err)
    if date_range[0] and date_range[1]:
        print(f"\n  Date range (SI created): {date_range[0][:19]} UTC", file=err)
        print(f"                       to: {date_range[1][:19]} UTC", file=err)
    if extensions:
        print(f"\n  Top file extensions:", file=err)
        for ext, count in sorted(extensions.items(), key=lambda x: -x[1])[:15]:
            label = ext if ext else "(no extension)"
            print(f"    {label:<20} {count:>8,}", file=err)
    print("\n" + "=" * W + "\n", file=err)


def main():
    ap = argparse.ArgumentParser(
        prog="mft-parse",
        description="Windows MFT parser for Linux. Outputs structured CSV.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s '$MFT' -o mft.csv
  %(prog)s '$MFT' -o mft.csv --summary
  %(prog)s '$MFT' -o mft.csv --deleted-only
  %(prog)s '$MFT' -o mft.csv --filter-ext exe,dll,ps1,bat

For KAPE collections:
  %(prog)s '/path/to/kape/C/$MFT' -o mft.csv --summary

For E01 images, mount first:
  ewfmount image.E01 /mnt/ewf && mount -r /mnt/ewf/ewf1 /mnt/image
  then point %(prog)s at /mnt/image/$MFT
        """,
    )
    ap.add_argument("input", help="$MFT file path")
    ap.add_argument("-o", "--output", default="-", metavar="FILE", help="Output CSV (default: stdout)")
    ap.add_argument("--summary", "-s", action="store_true", help="Print triage summary after parsing")
    ap.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")
    ap.add_argument("--deleted-only", action="store_true", help="Output only deleted entries")
    ap.add_argument("--allocated-only", action="store_true", help="Output only allocated entries")
    ap.add_argument("--filter-ext", default=None, metavar="EXTS",
                    help="Comma-separated extensions to include (e.g. exe,dll,ps1)")
    ap.add_argument("--discrepancy-only", action="store_true",
                    help="Output only entries with SI/FN timestamp discrepancies")
    ap.add_argument("--no-header", action="store_true", help="Suppress CSV header row")
    args = ap.parse_args()

    mft_path = Path(args.input)
    if not mft_path.exists():
        print(f"[!] File not found: {mft_path}", file=sys.stderr)
        sys.exit(1)

    ext_filter = {e.lower().lstrip(".") for e in args.filter_ext.split(",")} if args.filter_ext else None

    total = errors = deleted = dirs = discrepancies = disc_si_older = disc_si_newer = 0
    extensions: dict[str, int] = {}
    first_ts = last_ts = ""

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

        parser = PyMftParser(str(mft_path))
        for entry in parser.entries():
            row = parse_entry(entry, mft_path.name)
            if row is None:
                errors += 1
                continue

            total += 1
            if row["is_deleted"] == "Yes":
                deleted += 1
            if row["is_directory"] == "Yes":
                dirs += 1
            if row["si_fn_discrepancy"] == "Yes":
                discrepancies += 1
                if "SI<FN" in row["si_fn_direction"]:
                    disc_si_older += 1
                if "SI>FN" in row["si_fn_direction"]:
                    disc_si_newer += 1

            ext = row["extension"]
            if ext is not None:
                extensions[ext] = extensions.get(ext, 0) + 1

            ts = row["si_created"]
            if ts:
                if not first_ts or ts < first_ts:
                    first_ts = ts
                if not last_ts or ts > last_ts:
                    last_ts = ts

            # Apply filters
            if args.deleted_only and row["is_deleted"] != "Yes":
                continue
            if args.allocated_only and row["allocated"] != "Yes":
                continue
            if args.discrepancy_only and row["si_fn_discrepancy"] != "Yes":
                continue
            if ext_filter and row["extension"] not in ext_filter:
                continue

            try:
                writer.writerow(row)
            except Exception:
                errors += 1

        if not args.quiet:
            print(f"[+] Complete. Entries parsed: {total:,}, errors: {errors}", file=sys.stderr)

        if args.summary:
            print_summary(total, errors, deleted, dirs, discrepancies,
                          disc_si_older, disc_si_newer, extensions, (first_ts, last_ts))

    finally:
        if close_fh:
            out_fh.close()


if __name__ == "__main__":
    main()
