#!/usr/bin/env python3
"""
reg-parse: Windows registry hive parser for Linux
Parses SAM, SYSTEM, SOFTWARE, SECURITY, and NTUSER.DAT hives. Outputs structured CSV.

Timestamps: key last-written times and decoded binary timestamps are UTC.
Use alongside mft_parse.py and usn_parse.py output for a combined timeline.

SECURITY hive: extracts audit policy and cached domain logon timestamps only.
Credential material (hashes, LSA secrets) is not extracted - use impacket secretsdump for that.
"""

import argparse
import codecs
import csv
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from Registry import Registry
except ImportError:
    print("[!] python-registry not installed. Run: pip install python-registry", file=sys.stderr)
    sys.exit(1)


FIELDNAMES = [
    "timestamp",
    "hive",
    "artefact",
    "name",
    "value",
    "details",
    "key_path",
    "source_file",
]

HIVE_TYPES = ("sam", "system", "software", "security", "ntuser")


def fmt_ts(dt) -> str:
    if dt is None:
        return ""
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


def filetime_to_dt(ft: int):
    if ft == 0:
        return None
    try:
        ts = datetime(1601, 1, 1, tzinfo=timezone.utc).timestamp() + ft / 1e7
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except Exception:
        return None


def safe_open(reg, path: str):
    try:
        return reg.open(path)
    except Exception:
        return None


def make_row(ts, hive, artefact, name, value, details, key_path, source):
    return {
        "timestamp":   ts,
        "hive":        hive,
        "artefact":    artefact,
        "name":        name,
        "value":       str(value) if value is not None else "",
        "details":     details,
        "key_path":    key_path,
        "source_file": source,
    }


# ── SAM ────────────────────────────────────────────────────────────────────────

ACB_FLAGS = {
    0x0001: "DISABLED",
    0x0008: "NO_PASSWD",
    0x0010: "NORMAL",
    0x0200: "PASSWD_NEVER_EXPIRES",
    0x0400: "LOCKED",
}


def decode_acb(flags: int) -> str:
    return "|".join(name for mask, name in ACB_FLAGS.items() if flags & mask) or str(flags)


def parse_sam_f(data: bytes) -> dict:
    """Parse SAM user F value binary structure."""
    result = {}
    if len(data) < 68:
        return result
    try:
        last_logon_ft  = struct.unpack_from("<Q", data, 8)[0]
        pw_set_ft      = struct.unpack_from("<Q", data, 24)[0]
        last_failed_ft = struct.unpack_from("<Q", data, 40)[0]
        rid            = struct.unpack_from("<I", data, 48)[0]
        acb_flags      = struct.unpack_from("<I", data, 52)[0]
        failed_count   = struct.unpack_from("<H", data, 56)[0]
        login_count    = struct.unpack_from("<H", data, 58)[0]
        result["rid"]          = rid
        result["acb_flags"]    = decode_acb(acb_flags)
        result["last_logon"]   = fmt_ts(filetime_to_dt(last_logon_ft))
        result["pw_set"]       = fmt_ts(filetime_to_dt(pw_set_ft))
        result["last_failed"]  = fmt_ts(filetime_to_dt(last_failed_ft))
        result["failed_count"] = failed_count
        result["login_count"]  = login_count
    except Exception:
        pass
    return result


def parse_sam(reg, source: str) -> list:
    rows = []
    names_key = safe_open(reg, "SAM\\Domains\\Account\\Users\\Names")
    if names_key is None:
        return rows
    for name_key in names_key.subkeys():
        username = name_key.name()
        try:
            rid_val = name_key.value("(default)")
            rid = rid_val.value_type()
        except Exception:
            rid = 0
        rid_hex = f"{rid:08X}"
        users_key = safe_open(reg, f"SAM\\Domains\\Account\\Users\\{rid_hex}")
        f_data = {}
        if users_key:
            try:
                f_val = users_key.value("F")
                f_data = parse_sam_f(f_val.value())
            except Exception:
                pass
        parts = []
        if f_data.get("rid"):
            parts.append(f"RID={f_data['rid']}")
        if f_data.get("acb_flags"):
            parts.append(f"flags={f_data['acb_flags']}")
        if f_data.get("login_count") is not None:
            parts.append(f"logins={f_data['login_count']}")
        if f_data.get("failed_count") is not None:
            parts.append(f"failed={f_data['failed_count']}")
        if f_data.get("pw_set"):
            parts.append(f"pw_set={f_data['pw_set']}")
        if f_data.get("last_failed"):
            parts.append(f"last_failed={f_data['last_failed']}")
        ts = f_data.get("last_logon") or fmt_ts(name_key.timestamp())
        rows.append(make_row(ts, "SAM", "local_user", username,
                             f_data.get("last_logon", ""), " | ".join(parts),
                             name_key.path(), source))
    return rows


# ── SYSTEM ─────────────────────────────────────────────────────────────────────

SERVICE_START = {0: "Boot", 1: "System", 2: "Auto", 3: "Manual", 4: "Disabled"}
SERVICE_TYPE  = {1: "Kernel driver", 2: "FS driver", 16: "Own process", 32: "Share process"}


def _parse_shimcache(data: bytes) -> list[dict]:
    """Parse AppCompatCache binary blob.

    Supports the Windows 8.1 / 10 / Server 2016/2019 "10ts" format:
      - Header: first DWORD = header size in bytes (typically 0x30 = 48)
      - Entries start at offset header_size, each beginning with the "10ts" signature
      - Entry layout: sig(4) + unknown(4) + data_size(4) + path_len(2) + path(path_len)
                      + last_modified_FILETIME(8) + remaining_data(data_size - path_len - 10)

    Supports the Windows Vista / 7 "BADC0FFE" format as a fallback.
    """
    if len(data) < 16:
        return []

    entries = []
    header_dword = struct.unpack_from("<I", data, 0)[0]

    # "10ts" format: header_dword is the header size; entries follow immediately after
    if header_dword < len(data) and data[header_dword:header_dword + 4] == b"10ts":
        offset = header_dword
        order = 0
        while offset + 14 <= len(data):
            if data[offset:offset + 4] != b"10ts":
                break
            try:
                data_size = struct.unpack_from("<I", data, offset + 8)[0]
                if data_size < 10 or offset + 12 + data_size > len(data):
                    break
                path_len = struct.unpack_from("<H", data, offset + 12)[0]
                if path_len == 0 or offset + 14 + path_len > len(data):
                    break
                path = data[offset + 14:offset + 14 + path_len].decode(
                    "utf-16-le", errors="replace"
                ).rstrip("\x00")
                ft_offset = offset + 14 + path_len
                last_mod = ""
                if ft_offset + 8 <= len(data):
                    ft = struct.unpack_from("<Q", data, ft_offset)[0]
                    last_mod = fmt_ts(filetime_to_dt(ft))
                entries.append({"order": order, "path": path, "last_modified": last_mod})
                order += 1
                offset += 12 + data_size
            except (struct.error, UnicodeDecodeError):
                break

    # Vista / 7 format: header signature 0xBADC0FFE, 64-bit entries
    elif header_dword == 0xBADC0FFE:
        try:
            entry_count = struct.unpack_from("<I", data, 4)[0]
        except struct.error:
            return []
        offset = 128
        for order in range(min(entry_count, 4096)):
            if offset + 40 > len(data):
                break
            try:
                path_len    = struct.unpack_from("<H", data, offset)[0]
                path_offset = struct.unpack_from("<Q", data, offset + 8)[0]
                last_mod_ft = struct.unpack_from("<Q", data, offset + 16)[0]
                path = ""
                if path_offset + path_len <= len(data) and path_len > 0:
                    path = data[path_offset:path_offset + path_len].decode(
                        "utf-16-le", errors="replace"
                    ).rstrip("\x00")
                entries.append({
                    "order": order,
                    "path": path,
                    "last_modified": fmt_ts(filetime_to_dt(last_mod_ft)),
                })
                offset += 40
            except (struct.error, UnicodeDecodeError):
                break

    return entries


def parse_system(reg, source: str) -> list:
    rows = []

    select_key = safe_open(reg, "Select")
    current_cs = 1
    if select_key:
        try:
            current_cs = select_key.value("Current").value()
        except Exception:
            pass
    cs = f"ControlSet{current_cs:03d}"

    cn_key = safe_open(reg, f"{cs}\\Control\\ComputerName\\ComputerName")
    if cn_key:
        try:
            cn = cn_key.value("ComputerName").value()
            rows.append(make_row(fmt_ts(cn_key.timestamp()), "SYSTEM", "computer_name",
                                 "ComputerName", cn, f"ControlSet={current_cs}",
                                 cn_key.path(), source))
        except Exception:
            pass

    tz_key = safe_open(reg, f"{cs}\\Control\\TimeZoneInformation")
    if tz_key:
        try:
            tz_name = tz_key.value("TimeZoneKeyName").value()
            try:
                bias = tz_key.value("Bias").value()
                bias_str = f"Bias={bias} min"
            except Exception:
                bias_str = ""
            rows.append(make_row(fmt_ts(tz_key.timestamp()), "SYSTEM", "timezone",
                                 "TimeZoneKeyName", tz_name, bias_str,
                                 tz_key.path(), source))
        except Exception:
            pass

    svc_key = safe_open(reg, f"{cs}\\Services")
    if svc_key:
        for svc in svc_key.subkeys():
            try:
                image_path = start_type = svc_type = display = ""
                try:
                    image_path = svc.value("ImagePath").value()
                except Exception:
                    pass
                try:
                    start_type = SERVICE_START.get(svc.value("Start").value(), "")
                except Exception:
                    pass
                try:
                    svc_type = SERVICE_TYPE.get(svc.value("Type").value(), "")
                except Exception:
                    pass
                try:
                    display = svc.value("DisplayName").value()
                except Exception:
                    pass
                if not image_path:
                    continue
                details = f"start={start_type} | type={svc_type}"
                if display:
                    details += f" | display={display}"
                rows.append(make_row(fmt_ts(svc.timestamp()), "SYSTEM", "service",
                                     svc.name(), image_path, details,
                                     svc.path(), source))
            except Exception:
                continue

    shim_key = safe_open(reg, f"{cs}\\Control\\Session Manager\\AppCompatCache")
    if shim_key:
        try:
            shim_data = shim_key.value("AppCompatCache").value()
            shim_entries = _parse_shimcache(shim_data)
            for e in shim_entries:
                rows.append(make_row(
                    e["last_modified"], "SYSTEM", "shimcache",
                    e["path"], e["last_modified"],
                    f"order={e['order']}",
                    shim_key.path(), source,
                ))
            if not shim_entries:
                print("[!] shimcache: unrecognised format or no entries", file=sys.stderr)
        except Exception as ex:
            print(f"[!] shimcache parse error: {ex}", file=sys.stderr)

    usb_key = safe_open(reg, f"{cs}\\Enum\\USBSTOR")
    if usb_key:
        for dev_type in usb_key.subkeys():
            for instance in dev_type.subkeys():
                try:
                    friendly = ""
                    try:
                        friendly = instance.value("FriendlyName").value()
                    except Exception:
                        pass
                    rows.append(make_row(fmt_ts(instance.timestamp()), "SYSTEM", "usbstor",
                                         instance.name(), friendly,
                                         f"device_type={dev_type.name()}",
                                         instance.path(), source))
                except Exception:
                    continue

    return rows


# ── SOFTWARE ───────────────────────────────────────────────────────────────────

def parse_software(reg, source: str) -> list:
    rows = []

    os_key = safe_open(reg, "Microsoft\\Windows NT\\CurrentVersion")
    if os_key:
        fields = ["ProductName", "CurrentVersion", "CurrentBuildNumber",
                  "ReleaseId", "DisplayVersion", "InstallDate", "RegisteredOwner"]
        parts = []
        for f in fields:
            try:
                v = os_key.value(f).value()
                if f == "InstallDate" and isinstance(v, int):
                    dt = datetime.fromtimestamp(v, tz=timezone.utc)
                    parts.append(f"{f}={dt.strftime('%Y-%m-%d')}")
                else:
                    parts.append(f"{f}={v}")
            except Exception:
                pass
        rows.append(make_row(fmt_ts(os_key.timestamp()), "SOFTWARE", "os_version",
                             "CurrentVersion", "", " | ".join(parts),
                             os_key.path(), source))

    for uninstall_path in [
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ]:
        uk = safe_open(reg, uninstall_path)
        if not uk:
            continue
        for app in uk.subkeys():
            try:
                display_name = publisher = install_date = version = ""
                try: display_name = app.value("DisplayName").value()
                except Exception: pass
                try: publisher    = app.value("Publisher").value()
                except Exception: pass
                try: install_date = str(app.value("InstallDate").value())
                except Exception: pass
                try: version      = app.value("DisplayVersion").value()
                except Exception: pass
                if not display_name:
                    continue
                details = f"publisher={publisher} | version={version} | install_date={install_date}"
                rows.append(make_row(fmt_ts(app.timestamp()), "SOFTWARE", "installed_app",
                                     display_name, version, details,
                                     app.path(), source))
            except Exception:
                continue

    for run_path in [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    ]:
        rk = safe_open(reg, run_path)
        if not rk:
            continue
        for val in rk.values():
            try:
                rows.append(make_row(fmt_ts(rk.timestamp()), "SOFTWARE", "autorun",
                                     val.name(), str(val.value()), f"key={run_path}",
                                     rk.path(), source))
            except Exception:
                continue

    return rows


# ── NTUSER ─────────────────────────────────────────────────────────────────────

UA_GUIDS = {
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "exe",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "lnk",
}


def parse_userassist_data(data: bytes):
    """Returns (run_count, last_run_str). Struct layout for Win7+."""
    if len(data) < 72:
        return None, ""
    try:
        run_count = struct.unpack_from("<I", data, 4)[0]
        if run_count >= 5:
            run_count -= 5
        last_run_ft = struct.unpack_from("<Q", data, 60)[0]
        return run_count, fmt_ts(filetime_to_dt(last_run_ft))
    except Exception:
        return None, ""


def parse_ntuser(reg, source: str) -> list:
    rows = []

    for run_path in [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]:
        rk = safe_open(reg, run_path)
        if not rk:
            continue
        for val in rk.values():
            try:
                rows.append(make_row(fmt_ts(rk.timestamp()), "NTUSER", "autorun",
                                     val.name(), str(val.value()), f"key={run_path}",
                                     rk.path(), source))
            except Exception:
                continue

    ua_root = safe_open(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    if ua_root:
        for guid_key in ua_root.subkeys():
            guid = guid_key.name()
            ua_type = UA_GUIDS.get(guid.upper(), "unknown")
            count_key = safe_open(
                reg,
                f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{guid}\\Count"
            )
            if not count_key:
                continue
            for val in count_key.values():
                try:
                    decoded = codecs.decode(val.name(), "rot_13")
                    if decoded.startswith("UEME_"):
                        continue
                    run_count, last_run = parse_userassist_data(val.value())
                    ts = last_run or fmt_ts(count_key.timestamp())
                    rows.append(make_row(ts, "NTUSER", "userassist",
                                         decoded,
                                         str(run_count) if run_count is not None else "",
                                         f"type={ua_type}",
                                         count_key.path(), source))
                except Exception:
                    continue

    rd_key = safe_open(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs")
    if rd_key:
        for subkey in [rd_key] + list(rd_key.subkeys()):
            try:
                for val in subkey.values():
                    if val.name() == "MRUListEx":
                        continue
                    try:
                        raw = val.value()
                        if isinstance(raw, bytes):
                            null = raw.find(b'\x00\x00')
                            name_str = raw[:null + 1].decode("utf-16-le", errors="replace").rstrip("\x00") if null > 0 else raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                        else:
                            name_str = str(raw)
                        rows.append(make_row(fmt_ts(subkey.timestamp()), "NTUSER", "recentdoc",
                                             name_str, val.name(),
                                             f"ext_group={subkey.name()}",
                                             subkey.path(), source))
                    except Exception:
                        continue
            except Exception:
                continue

    rmru_key = safe_open(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
    if rmru_key:
        for val in rmru_key.values():
            if val.name() == "MRUList":
                continue
            try:
                rows.append(make_row(fmt_ts(rmru_key.timestamp()), "NTUSER", "runmru",
                                     val.name(), str(val.value()), "",
                                     rmru_key.path(), source))
            except Exception:
                continue

    return rows


# ── SECURITY ───────────────────────────────────────────────────────────────────

AUDIT_CATEGORIES = {
    "0": "No auditing",
    "1": "Success",
    "2": "Failure",
    "3": "Success and Failure",
}

AUDIT_POLICY_KEYS = {
    "AuditSystemEvents":          "System Events",
    "AuditLogonEvents":           "Logon Events",
    "AuditObjectAccess":          "Object Access",
    "AuditPrivilegeUse":          "Privilege Use",
    "AuditProcessTracking":       "Process Tracking",
    "AuditPolicyChange":          "Policy Change",
    "AuditAccountManage":         "Account Management",
    "AuditDSAccess":              "Directory Service Access",
    "AuditAccountLogon":          "Account Logon",
}


def filetime_from_bytes(data: bytes, offset: int):
    if offset + 8 > len(data):
        return None
    ft = struct.unpack_from("<Q", data, offset)[0]
    return filetime_to_dt(ft)


def parse_security(reg, source: str) -> list:
    rows = []

    # Audit policy (legacy - PolAdtEv value)
    pol_key = safe_open(reg, "Policy\\PolAdtEv")
    if pol_key:
        try:
            data = pol_key.value("(default)").value()
            # PolAdtEv binary layout: 4-byte header, then one DWORD per category (POLICY_AUDIT_EVENT_OPTIONS)
            # Raw DWORD values: 0=no change, non-zero=bitmask of audit options per MS-LSAD spec
            category_names = list(AUDIT_POLICY_KEYS.values())
            for i, name in enumerate(category_names):
                offset = 4 + (i * 4)
                if offset + 4 <= len(data):
                    raw = struct.unpack_from("<I", data, offset)[0]
                    rows.append(make_row(
                        fmt_ts(pol_key.timestamp()), "SECURITY", "audit_policy",
                        name, str(raw), "raw POLICY_AUDIT_EVENT_OPTIONS flags",
                        pol_key.path(), source
                    ))
        except Exception:
            pass

    # Cached domain logon timestamps (NL$Cache)
    # Username and domain are encrypted with NL$KM - only the timestamp and entry slot are extractable.
    # For decrypted account names use impacket secretsdump.
    cache_key = safe_open(reg, "Cache")
    if cache_key:
        for val in cache_key.values():
            if not val.name().startswith("NL$") or val.name() == "NL$Control":
                continue
            try:
                data = val.value()
                if not isinstance(data, bytes) or len(data) < 40:
                    continue
                username_len = struct.unpack_from("<H", data, 0)[0]
                if username_len == 0:
                    continue
                # FILETIME is at offset 32 in the NL$Cache header
                last_write = filetime_from_bytes(data, 32)
                ts = fmt_ts(last_write) if last_write else ""
                rows.append(make_row(
                    ts, "SECURITY", "cached_logon",
                    val.name(), ts,
                    "username encrypted - use impacket secretsdump for account names",
                    cache_key.path(), source
                ))
            except Exception:
                continue

    return rows


# ── Summary ────────────────────────────────────────────────────────────────────

def print_summary(hive_type: str, total: int, errors: int, artefact_counts: dict):
    err = sys.stderr
    W = 60
    print("\n" + "=" * W, file=err)
    print(f"  REGISTRY TRIAGE SUMMARY ({hive_type.upper()})", file=err)
    print("=" * W, file=err)
    print(f"\n  Total records    : {total:,}", file=err)
    print(f"  Parse errors     : {errors:,}", file=err)
    print(f"\n  Records by artefact:", file=err)
    for artefact, count in sorted(artefact_counts.items(), key=lambda x: -x[1]):
        print(f"    {artefact:<30} {count:>8,}", file=err)
    print("\n" + "=" * W + "\n", file=err)


# ── Main ───────────────────────────────────────────────────────────────────────

PARSERS = {
    "sam":      parse_sam,
    "system":   parse_system,
    "software": parse_software,
    "security": parse_security,
    "ntuser":   parse_ntuser,
}


def main():
    ap = argparse.ArgumentParser(
        prog="reg-parse",
        description="Windows registry hive parser for Linux. Outputs structured CSV.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s SAM --hive sam -o sam.csv --summary
  %(prog)s SYSTEM --hive system -o system.csv --summary
  %(prog)s SOFTWARE --hive software -o software.csv --summary
  %(prog)s NTUSER.DAT --hive ntuser -o ntuser.csv --summary

For KAPE collections:
  %(prog)s '/path/to/kape/C/Windows/System32/config/SAM' --hive sam -o sam.csv --summary
  %(prog)s '/path/to/kape/C/Windows/System32/config/SECURITY' --hive security -o security.csv --summary
  %(prog)s '/path/to/kape/C/Users/Administrator/NTUSER.DAT' --hive ntuser -o ntuser.csv --summary
        """,
    )
    ap.add_argument("input", help="Hive file path")
    ap.add_argument("--hive", required=True, choices=HIVE_TYPES,
                    help="Hive type: sam, system, software, ntuser")
    ap.add_argument("-o", "--output", default="-", metavar="FILE",
                    help="Output CSV (default: stdout)")
    ap.add_argument("--summary", "-s", action="store_true",
                    help="Print triage summary after parsing")
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="Suppress progress output")
    ap.add_argument("--no-header", action="store_true",
                    help="Suppress CSV header row")
    args = ap.parse_args()

    hive_path = Path(args.input)
    if not hive_path.exists():
        print(f"[!] File not found: {hive_path}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"[*] Opening {hive_path} as {args.hive.upper()} hive…", file=sys.stderr)

    try:
        reg = Registry.Registry(str(hive_path))
    except Exception as e:
        print(f"[!] Failed to open hive: {e}", file=sys.stderr)
        sys.exit(1)

    parse_fn = PARSERS[args.hive]
    try:
        all_rows = parse_fn(reg, hive_path.name)
    except Exception as e:
        print(f"[!] Parse error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output == "-":
        out_fh = sys.stdout
        close_fh = False
    else:
        out_fh = open(args.output, "w", newline="", encoding="utf-8")
        close_fh = True

    total = errors = 0
    artefact_counts: dict[str, int] = {}

    try:
        writer = csv.DictWriter(out_fh, fieldnames=FIELDNAMES, extrasaction="ignore")
        if not args.no_header:
            writer.writeheader()
        for r in all_rows:
            total += 1
            artefact_counts[r["artefact"]] = artefact_counts.get(r["artefact"], 0) + 1
            try:
                writer.writerow(r)
            except Exception:
                errors += 1
    finally:
        if close_fh:
            out_fh.close()

    if not args.quiet:
        print(f"[+] Complete. Records written: {total:,}, errors: {errors}", file=sys.stderr)

    if args.summary:
        print_summary(args.hive, total, errors, artefact_counts)


if __name__ == "__main__":
    main()
