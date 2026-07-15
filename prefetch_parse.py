#!/usr/bin/env python3
"""Parse Windows Prefetch files (.pf) into timeline CSV."""

import csv
import datetime
import glob
import os
import struct
import sys
from pathlib import Path

try:
    from dissect.util.compression import lzxpress_huffman
    HAS_DISSECT = True
except ImportError:
    HAS_DISSECT = False

FIELDNAMES = [
    "timestamp", "executable", "hash", "run_count", "run_number",
    "volume_path", "volume_serial", "files_loaded", "referenced_files",
    "source_file",
]

MAM_SIG = b"MAM\x04"
SCCA_SIG = b"SCCA"


def _filetime_to_dt(ft: int):
    if ft == 0:
        return None
    try:
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return epoch + datetime.timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


def _fmt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""


def _decompress(data: bytes) -> bytes:
    if data[:4] == MAM_SIG:
        if not HAS_DISSECT:
            raise RuntimeError(
                "MAM-compressed prefetch requires dissect.util: pip install dissect.util"
            )
        return lzxpress_huffman.decompress(data[8:])
    return data


def _extract_files(data: bytes, sec_a_off: int, sec_a_cnt: int, sec_c_off: int) -> list[str]:
    files = []
    for i in range(sec_a_cnt):
        entry = sec_a_off + i * 32
        if entry + 32 > len(data):
            break
        fn_off = struct.unpack_from("<I", data, entry + 12)[0]
        fn_len = struct.unpack_from("<I", data, entry + 16)[0]
        abs_off = sec_c_off + fn_off
        raw = data[abs_off: abs_off + fn_len * 2]
        path = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if path:
            files.append(path)
    return files


def parse_pf(path: str) -> list[dict]:
    try:
        with open(path, "rb") as f:
            raw = f.read()
        data = _decompress(raw)
    except Exception:
        return []

    if len(data) < 84 or data[4:8] != SCCA_SIG:
        return []

    version = struct.unpack_from("<I", data, 0)[0]
    exe_raw = data[16:76].decode("utf-16-le", errors="replace").rstrip("\x00")
    pf_hash = struct.unpack_from("<I", data, 76)[0]
    fi = 84

    if version in (30, 31):
        sec_a_off = struct.unpack_from("<I", data, fi + 0)[0]
        sec_a_cnt = struct.unpack_from("<I", data, fi + 4)[0]
        sec_c_off = struct.unpack_from("<I", data, fi + 16)[0]
        sec_d_off = struct.unpack_from("<I", data, fi + 24)[0]
        sec_d_cnt = struct.unpack_from("<I", data, fi + 28)[0]

        run_times = []
        for i in range(8):
            ft = struct.unpack_from("<Q", data, fi + 44 + i * 8)[0]
            dt = _filetime_to_dt(ft)
            if dt:
                run_times.append(dt)

        run_count = struct.unpack_from("<I", data, fi + 116)[0]

    elif version == 26:
        sec_a_off = struct.unpack_from("<I", data, fi + 0)[0]
        sec_a_cnt = struct.unpack_from("<I", data, fi + 4)[0]
        sec_c_off = struct.unpack_from("<I", data, fi + 16)[0]
        sec_d_off = struct.unpack_from("<I", data, fi + 24)[0]
        sec_d_cnt = struct.unpack_from("<I", data, fi + 28)[0]

        ft = struct.unpack_from("<Q", data, fi + 36)[0]
        dt = _filetime_to_dt(ft)
        run_times = [dt] if dt else []
        run_count = struct.unpack_from("<I", data, fi + 60)[0]

    else:
        return []

    # Volume info: device path and serial from first volume
    volume_path = ""
    volume_serial = ""
    if sec_d_cnt > 0 and sec_d_off + 24 <= len(data):
        dev_path_off = struct.unpack_from("<I", data, sec_d_off + 0)[0]
        dev_path_len = struct.unpack_from("<I", data, sec_d_off + 4)[0]
        vol_serial   = struct.unpack_from("<I", data, sec_d_off + 16)[0]
        path_abs = sec_d_off + dev_path_off
        if path_abs + dev_path_len * 2 <= len(data):
            volume_path = data[path_abs: path_abs + dev_path_len * 2].decode(
                "utf-16-le", errors="replace"
            ).rstrip("\x00")
        volume_serial = f"{vol_serial:08X}"

    # Referenced files from SectionA metrics
    files = _extract_files(data, sec_a_off, sec_a_cnt, sec_c_off)
    files_str = "|".join(files)

    rows = []
    for i, dt in enumerate(run_times):
        rows.append({
            "timestamp":        _fmt(dt),
            "executable":       exe_raw,
            "hash":             f"{pf_hash:08X}",
            "run_count":        run_count,
            "run_number":       i + 1,
            "volume_path":      volume_path,
            "volume_serial":    volume_serial,
            "files_loaded":     sec_a_cnt,
            "referenced_files": files_str,
            "source_file":      path,
        })

    # If there are no run times but a non-zero run count, emit one row with no timestamp
    if not rows and run_count:
        rows.append({
            "timestamp":        "",
            "executable":       exe_raw,
            "hash":             f"{pf_hash:08X}",
            "run_count":        run_count,
            "run_number":       "",
            "volume_path":      volume_path,
            "volume_serial":    volume_serial,
            "files_loaded":     sec_a_cnt,
            "referenced_files": files_str,
            "source_file":      path,
        })

    return rows


def _collect_paths(inputs: list[str]) -> list[str]:
    paths = []
    for inp in inputs:
        p = Path(inp)
        if p.is_dir():
            paths.extend(str(x) for x in sorted(p.rglob("*.pf")))
            paths.extend(str(x) for x in sorted(p.rglob("*.PF")))
        elif p.is_file():
            paths.append(str(p))
        else:
            expanded = glob.glob(inp, recursive=True)
            paths.extend(sorted(expanded))
    return paths


def _summary(all_rows: list[dict]) -> None:
    executables: dict[str, list[dict]] = {}
    for row in all_rows:
        executables.setdefault(row["executable"], []).append(row)

    print(f"\nTotal prefetch files parsed:  {len(executables)}")
    print(f"Total execution events:       {len(all_rows)}")
    print()

    # Sort by most recent run time descending
    def latest(rows):
        ts = [r["timestamp"] for r in rows if r["timestamp"]]
        return max(ts) if ts else ""

    sorted_exes = sorted(executables.items(), key=lambda kv: latest(kv[1]), reverse=True)

    print(f"{'Executable':<40}  {'Run count':>9}  {'Last run (UTC)':>19}  {'Files loaded':>12}")
    print("-" * 90)
    for exe, rows in sorted_exes:
        rc = rows[0]["run_count"]
        ts = latest(rows)
        fl = rows[0]["files_loaded"]
        print(f"  {exe:<38}  {rc:>9}  {ts:>19}  {fl:>12}")


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="Parse Windows Prefetch files into timeline CSV."
    )
    ap.add_argument("input", nargs="+", help="Prefetch file(s) or directory")
    ap.add_argument("-o", "--output", default="-", help="Output CSV (default: stdout)")
    ap.add_argument("--summary", action="store_true", help="Print triage summary")
    ap.add_argument(
        "--no-files",
        action="store_true",
        help="Omit referenced_files column (reduces CSV size)",
    )
    args = ap.parse_args()

    paths = _collect_paths(args.input)
    if not paths:
        print("No prefetch files found.", file=sys.stderr)
        sys.exit(1)

    all_rows = []
    errors = 0
    for p in paths:
        rows = parse_pf(p)
        if not rows:
            errors += 1
        all_rows.extend(rows)

    fields = FIELDNAMES if not args.no_files else [f for f in FIELDNAMES if f != "referenced_files"]

    if args.output == "-":
        writer = csv.DictWriter(sys.stdout, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(all_rows)
    else:
        with open(args.output, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
            writer.writeheader()
            writer.writerows(all_rows)
        print(f"Wrote {len(all_rows)} rows to {args.output}", file=sys.stderr)

    if errors:
        print(f"Warning: {errors} file(s) could not be parsed.", file=sys.stderr)

    if args.summary:
        _summary(all_rows)


if __name__ == "__main__":
    main()
