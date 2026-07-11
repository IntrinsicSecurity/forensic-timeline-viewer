#!/usr/bin/env python3
"""
shellbags_parse.py - Parse Windows ShellBag entries from UsrClass.dat or NTUSER.DAT.

ShellBags record folders a user has browsed via Windows Explorer, including
folders on network shares, USB devices, and paths that no longer exist.

Accepts a single hive file or a Users directory (recurses to find UsrClass.dat
and NTUSER.DAT for each user).

Usage:
    python3 shellbags_parse.py /kape/C/Users/ -o shellbags.csv --summary
    python3 shellbags_parse.py /kape/C/Users/davec.admin/AppData/Local/Microsoft/Windows/UsrClass.dat -o shellbags.csv
"""

import argparse
import csv
import os
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from Registry import Registry
except ImportError:
    print("[!] python-registry not installed. Run: pip install python-registry", file=sys.stderr)
    sys.exit(1)


# ── DOS date/time helpers ────────────────────────────────────────────────────

def _dos_datetime(dos_date: int, dos_time: int) -> str:
    if dos_date == 0:
        return ""
    try:
        day   = dos_date & 0x1F
        month = (dos_date >> 5) & 0x0F
        year  = ((dos_date >> 9) & 0x7F) + 1980
        sec   = (dos_time & 0x1F) * 2
        minute = (dos_time >> 5) & 0x3F
        hour  = (dos_time >> 11) & 0x1F
        dt = datetime(year, month, day, hour, minute, min(sec, 59), tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError):
        return ""


def _filetime_to_utc(filetime: int) -> str:
    if filetime == 0:
        return ""
    try:
        unix_us = (filetime - 116_444_736_000_000_000) // 10
        dt = datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return ""


def _regtime_to_utc(regtime) -> str:
    try:
        return regtime.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


# ── GUID resolution ──────────────────────────────────────────────────────────

# GUIDs stored in registry binary format (mixed-endian). Map from canonical
# string form {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} to friendly name.
_KNOWN_GUIDS = {
    "{20D04FE0-3AEA-1069-A2D8-08002B30309D}": "My Computer",
    "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}": "Network",
    "{208D2C60-3AEA-1069-A2D7-08002B30309D}": "My Network Places",
    "{645FF040-5081-101B-9F08-00AA002F954E}": "Recycle Bin",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "Desktop",
    "{450D8FBA-AD25-11D0-98A8-0800361B1103}": "My Documents",
    "{59031A47-3F72-44A7-89C5-5595FE6B30EE}": "Users",
    "{031E4825-7B94-4DC3-B131-E946B44C8DD5}": "Libraries",
    "{1CF1260C-4DD0-4EBB-811F-33C572699FDE}": "Music",
    "{3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}": "Pictures",
    "{A0953C92-50DC-43BF-BE83-3742FED03C9C}": "Videos",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "Program Files",
    "{905E63B6-C1BF-494E-B29C-65B732D3D21A}": "Program Files",
    "{374DE290-123F-4565-9164-39C4925E467B}": "Downloads",
    "{4BD8D571-6D19-48D3-BE97-422220080E43}": "Music",
    "{33E28130-4E1E-4676-835A-98395C3BC3BB}": "Pictures",
    "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}": "Videos",
    "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "Documents",
    "{B97D20BB-F46A-4C97-BA10-5E3608430854}": "Startup",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "Programs",
    "{9E52AB10-F80D-49DF-ACB8-4330F5687855}": "Temporary Internet Files",
    "{8983036C-27C0-404B-8F08-102D10DCFD74}": "SendTo",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "Programs",
    "{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}": "Startup",
    "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": "LocalAppData",
    "{A305CE99-F527-492B-8B1A-7E76FA98D6E4}": "Installed Updates",
    "{1777F761-68AD-4D8A-87BD-30B759FA33DD}": "Favorites",
    "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}": "Public Desktop",
    "{ED4824AF-DCE4-45A8-81E2-FC7965083634}": "Public Documents",
    "{3214FAB5-9757-4298-BB61-92A9DEAA44FF}": "Public Music",
    "{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}": "Public Pictures",
    "{2400183A-6185-49FB-A2D8-4A392A602BA3}": "Public Videos",
    "{DF7266AC-9274-4867-8D55-3BD661DE872D}": "Control Panel",
    "{26EE0668-A00A-44D7-9371-BEB064C98683}": "Control Panel",
    "{21EC2020-3AEA-1069-A2DD-08002B30309D}": "Control Panel",
    "{4234D49B-0245-4DF3-B780-3893943456E1}": "Applications",
    "{9C60DE1E-E5FC-40F4-A487-460851A8D915}": "Network Shortcuts",
    "{BDBF0C18-8685-4D3A-9BC7-76561A785F8D}": "Sync Results",
    "{00C6D95F-329C-409A-81D7-C46C66EA7F33}": "Default Location",
    "{679F85CB-0220-4080-B29B-5540CC05AAB6}": "Quick Access",
    "{52528A6B-B9E3-4ADD-B60D-588C2DBA842D}": "Homegroup",
    "{B4FB3F98-C1EA-428D-A78A-D1F5659CBA93}": "Other Users",
    "{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}": "3D Objects",
    "{9C2423C4-B7C5-4562-BFAC-81E63C4B56A2}": "Recorded TV",
}


def _resolve_guid(raw: bytes) -> str:
    """Convert 16 raw bytes (mixed-endian GUID) to a friendly name."""
    if len(raw) < 16:
        return "Root"
    try:
        d1 = struct.unpack_from("<I", raw, 0)[0]
        d2 = struct.unpack_from("<H", raw, 4)[0]
        d3 = struct.unpack_from("<H", raw, 6)[0]
        d4 = raw[8:16]

        # Windows drive letter GUIDs: {B710002F-F5A6-0019-2FXX-3A5C00000000}
        # where XX is the ASCII code of the drive letter (e.g. 0x43 = C)
        if (d1 == 0xB710002F and d2 == 0xF5A6 and d3 == 0x0019
                and d4[0] == 0x2F and d4[2] == 0x3A and d4[3] == 0x5C):
            drive_letter = chr(d4[1]).upper()
            if drive_letter.isalpha():
                return f"{drive_letter}:"

        guid_str = (
            f"{{{d1:08X}-{d2:04X}-{d3:04X}-"
            f"{d4[0]:02X}{d4[1]:02X}-"
            f"{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}}}"
        )
        return _KNOWN_GUIDS.get(guid_str, f"Root({guid_str})")
    except (struct.error, IndexError):
        return "Root"


def _extract_propstore_string(data: bytes) -> str:
    """Extract the most plausible hostname/sharename from a Shell Property Set item.

    These items (type 0x00) store their content as one or more property set blobs
    prefixed with the signature 0x53505331 ('1SPS'). The display name is stored
    as a null-terminated UTF-16LE string within one of those blobs.
    We scan all UTF-16LE candidate strings and return the longest one that looks
    like a hostname or UNC path component.
    """
    SPS = b"\x31\x53\x50\x53"  # '1SPS' property set signature
    candidates = []
    pos = 0
    while True:
        pos = data.find(SPS, pos)
        if pos < 0:
            break
        # Scan forward from this blob for null-terminated UTF-16LE strings
        i = pos + 4
        while i + 1 < len(data):
            # Look for a run of printable UTF-16LE characters followed by 0x0000
            if data[i + 1] == 0x00 and 0x20 <= data[i] <= 0x7E:
                start = i
                end = start
                while end + 1 < len(data):
                    if data[end] == 0 and data[end + 1] == 0:
                        break
                    end += 2
                try:
                    s = data[start:end].decode("utf-16-le", errors="strict").strip()
                    if len(s) >= 3 and all(c.isprintable() for c in s):
                        candidates.append(s)
                    i = end + 2
                    continue
                except (UnicodeDecodeError, ValueError):
                    pass
            i += 1
        pos += 4

    if not candidates:
        return ""
    # Prefer strings that look like hostnames or UNC paths
    for c in sorted(candidates, key=len, reverse=True):
        if any(ch in c for ch in (".", "\\", "-")) or c.lower().startswith("wft") or len(c) > 5:
            return c
    return max(candidates, key=len)


# ── Shell item binary parser ─────────────────────────────────────────────────

def _parse_shell_item(data: bytes) -> dict:
    """Parse a single shell item blob. Returns dict with name, modified, type_desc."""
    result = {"name": "", "modified": "", "type_desc": ""}
    if len(data) < 3:
        return result

    item_type = data[2]
    type_hi = item_type & 0xF0
    type_lo = item_type & 0x0F

    # Root/GUID items (Desktop, My Computer, etc.)
    if item_type == 0x1F:
        if len(data) >= 20:
            # GUIDs in shell items are stored as mixed-endian (GUID binary format):
            # first 4 bytes LE DWORD, next 2 bytes LE WORD, next 2 bytes LE WORD, then 8 bytes BE
            # Convert to standard string form for lookup
            name = _resolve_guid(data[4:20])
            result["name"] = name
            result["type_desc"] = "Root"
        return result

    # Volume / drive letter (0x2F and 0x2E)
    if item_type in (0x2F, 0x2E):
        name = ""
        try:
            null = data.index(0, 3)
            candidate = data[3:null].decode("ascii", errors="replace").rstrip("\\").strip()
            # Validate: expect "X:" or "X:\" format
            if len(candidate) >= 2 and candidate[0].isalpha() and candidate[1] == ":":
                name = candidate[:2]
        except (ValueError, IndexError):
            pass
        result["name"] = name or "Volume"
        result["type_desc"] = "Volume"
        return result

    # File / folder items (0x30–0x3F)
    if type_hi == 0x30:
        result["type_desc"] = "Folder" if (type_lo & 0x01) else "File"
        if len(data) < 0x10:
            return result
        try:
            dos_date = struct.unpack_from("<H", data, 0x08)[0]
            dos_time = struct.unpack_from("<H", data, 0x0A)[0]
            result["modified"] = _dos_datetime(dos_date, dos_time)
        except struct.error:
            pass

        # Bit 0x04 in the type byte indicates Unicode name at 0x0E (Vista+)
        if item_type & 0x04:
            end = 0x0E
            while end + 1 < len(data):
                if data[end] == 0 and data[end + 1] == 0:
                    break
                end += 2
            try:
                short_name = data[0x0E:end].decode("utf-16-le", errors="replace").strip()
            except UnicodeDecodeError:
                short_name = ""
        else:
            try:
                null = data.index(0, 0x0E)
                short_name = data[0x0E:null].decode("ascii", errors="replace").strip()
            except (ValueError, IndexError):
                short_name = ""

        # Prefer the BEEF0004 long name — more reliable and always Unicode
        long_name = _extract_long_name(data)
        result["name"] = long_name or short_name
        return result

    # Network share items (0x40–0x4F, and 0xC3 for newer network items)
    if type_hi == 0x40 or item_type == 0xC3:
        result["type_desc"] = "Network"
        # Name is at offset 5 for standard network items
        for start in (0x05, 0x04, 0x06):
            try:
                null = data.index(0, start)
                candidate = data[start:null].decode("ascii", errors="replace").strip()
                if candidate and all(c.isprintable() for c in candidate):
                    result["name"] = candidate
                    break
            except (ValueError, IndexError):
                continue
        return result

    # URI / URL items
    if item_type in (0x61, 0x62):
        result["type_desc"] = "URI"
        try:
            # URI data starts after fixed header; scan for http/ftp/\\ pattern
            text = data[0x10:].decode("utf-8", errors="ignore")
            for proto in ("http://", "https://", "ftp://", "\\\\"):
                idx = text.lower().find(proto)
                if idx >= 0:
                    result["name"] = text[idx:].split("\x00")[0]
                    break
        except Exception:
            pass
        return result

    # Individual Control Panel applet items (type 0x71).
    # Structure: size(2) + type(1) + unknown(1) + padding(10) + CLSID(16)
    # Source: libyal/libfwsi Windows Shell Item format specification.
    if item_type == 0x71:
        result["type_desc"] = "Control Panel"
        _CP_APPLETS = {
            "{BB06C0E4-D293-4F75-8A90-CB05B6477EEE}": "System",
            "{D20EA4E1-3957-11D2-A40B-0C5020524153}": "Administrative Tools",
            "{7007ACC7-3202-11D1-AAD2-00805FC1270E}": "Network Connections",
            "{8E908FC9-BECC-40F6-915B-F4CA0E70D03D}": "Network and Sharing Centre",
            "{7B81BE6A-CE2B-4676-A29E-EB907A5126C5}": "Programs and Features",
            "{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}": "Action Centre",
            "{28803F59-3A75-4058-995F-4EE5503B023C}": "Bluetooth Devices",
            "{B2C761C6-29BC-4F19-9251-E6195265BAF1}": "Colour Management",
            "{1206F5F1-0569-412C-8FEC-3204630DFB70}": "Credential Manager",
            "{E2E7934B-DCE5-43C4-9576-7FE4F75E7480}": "Date and Time",
            "{17CD9488-1228-4B2F-88CE-4298E93E0966}": "Default Programs",
            "{74246BFC-4C96-11D0-ABEF-0020AF6B0B7A}": "Device Manager",
            "{A8A91A66-3A7D-4424-8D24-04E180695C7A}": "Devices and Printers",
            "{D555645E-D4F8-4C29-A827-D93C859C4F2A}": "Ease of Access Centre",
            "{6DFD7C5C-2451-11D3-A299-00C04F8EF6AF}": "Folder Options",
            "{87D66A43-7B11-4A28-9811-C86EE395ACF7}": "Indexing Options",
            "{A3DD4F92-658A-410F-84FD-6FBBBEF2FFFE}": "Internet Options",
            "{725BE8F7-668E-4C7B-8F90-46BDB0936430}": "Keyboard",
            "{6C8EEC18-8D75-41B2-A177-8831D59D2D50}": "Mouse",
            "{40419485-C444-4567-851A-2DD7BFA1684D}": "Phone and Modem",
            "{025A5937-A6BE-4686-A844-36FE4BEC8B6D}": "Power Options",
            "{863AA9FD-42DF-457B-8E4D-0DE1B8015C60}": "Printers",
            "{62D8ED13-C9D0-4CE8-A914-47DD628FB1B0}": "Region and Language",
            "{F2DDFC82-8F12-4CDD-B7DC-D4FE1425AA4D}": "Sound",
            "{0DF44EAA-FF21-4412-828E-260A8728E7F1}": "Taskbar and Start Menu",
            "{C58C4893-3BE0-4B45-ABB5-A63E4B8C8651}": "Troubleshooting",
            "{60632754-C523-4B62-B45C-4172DA012619}": "User Accounts",
            "{4026492F-2F69-46B8-B9BF-5654FC07E423}": "Windows Firewall",
            "{36EEF7DB-88AD-4E81-AD49-0E313F0C35F8}": "Windows Update",
            "{58E3C745-D971-4081-9034-86E34B30836A}": "Speech Recognition",
        }
        try:
            if len(data) >= 30:
                raw = data[14:30]
                d1 = struct.unpack_from("<I", raw, 0)[0]
                d2 = struct.unpack_from("<H", raw, 4)[0]
                d3 = struct.unpack_from("<H", raw, 6)[0]
                d4 = raw[8:16]
                guid = (f"{{{d1:08X}-{d2:04X}-{d3:04X}-"
                        f"{d4[0]:02X}{d4[1]:02X}-"
                        f"{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}}}")
                result["name"] = _CP_APPLETS.get(guid, f"Applet({guid})")
        except (struct.error, IndexError):
            pass
        return result

    # Control Panel category items (type 0x01).
    # Structure: size(2) + type(1) + unknown(1) + sig(4) = 0x39DE2184 + category_id(4)
    # Source: libyal/libfwsi Windows Shell Item format specification.
    if item_type == 0x01:
        result["type_desc"] = "Control Panel"
        _CP_CATEGORIES = {
            0: "All Control Panel Items",
            1: "Appearance and Personalisation",
            2: "Hardware and Sound",
            3: "Network and Internet",
            4: "Sounds, Speech, and Audio Devices",
            5: "System and Security",
            6: "Clock, Language, and Region",
            7: "Ease of Access",
            8: "Programs",
            9: "User Accounts",
            10: "Security Centre",
            11: "Mobile PC",
        }
        try:
            sig = struct.unpack_from("<I", data, 4)[0]
            if sig == 0x39DE2184 and len(data) >= 12:
                cat_id = struct.unpack_from("<I", data, 8)[0]
                result["name"] = _CP_CATEGORIES.get(cat_id, f"Category {cat_id}")
        except struct.error:
            pass
        return result

    # Type 0x00: Shell Property Set items (Vista+). Used for network server
    # name items and for Control Panel virtual extension items (e.g. appwiz.cpl).
    # Distinguish by the extracted name: .cpl suffix indicates a Control Panel item.
    if item_type == 0x00:
        name = _extract_propstore_string(data)
        if name.lower().endswith(".cpl"):
            result["type_desc"] = "Control Panel"
        else:
            result["type_desc"] = "Network"
        result["name"] = name
        return result

    result["type_desc"] = f"0x{item_type:02X}"
    return result


def _extract_long_name(data: bytes) -> str:
    """Scan for BEEF0004 extension block and extract Unicode long name.

    Confirmed layout (offsets from ext_base = signature_pos - 4):
      +0   cb (2 bytes)
      +2   wVersion (2 bytes)
      +4   dwSignature = 0xBEEF0004 (4 bytes)
      +8   ftCreated (4 bytes DOS date/time pair)
      +12  ftAccessed (4 bytes DOS date/time pair)
      +16  wIdOffset (2 bytes) — offset from ext_base to start of Unicode name
      +18  ANSI long name (null-terminated, often empty)
      [Unicode name at ext_base + wIdOffset]
    """
    BEEF = b"\x04\x00\xef\xbe"
    pos = data.find(BEEF)
    if pos < 4:
        return ""
    try:
        ext_base = pos - 4
        wIdOffset = struct.unpack_from("<H", data, ext_base + 16)[0]

        if wIdOffset > 0:
            # wIdOffset is a direct offset from ext_base to the Unicode name.
            # Try +0 first (confirmed correct for version 9 items). If the
            # first two bytes don't look like a UTF-16LE character, try +2
            # in case an older extension block version has a 2-byte prefix.
            for adj in (0, 2):
                unicode_start = ext_base + wIdOffset + adj
                if unicode_start + 1 >= len(data):
                    continue
                # Sanity: first char should look like a UTF-16LE BMP character
                if not (0x20 <= data[unicode_start] <= 0x7E and data[unicode_start + 1] == 0x00):
                    continue
                end = unicode_start
                while end + 1 < len(data):
                    if data[end] == 0 and data[end + 1] == 0:
                        break
                    end += 2
                try:
                    name = data[unicode_start:end].decode("utf-16-le", errors="replace").strip()
                    if name and name not in (".", ""):
                        return name
                except UnicodeDecodeError:
                    pass

        # Fallback: ANSI long name at ext_base + 18
        ansi_start = ext_base + 18
        if ansi_start < len(data):
            try:
                null_pos = data.index(b"\x00", ansi_start)
                ansi_name = data[ansi_start:null_pos].decode("ascii", errors="replace").strip()
                if ansi_name and ansi_name not in (".", ""):
                    return ansi_name
            except ValueError:
                pass

        return ""
    except (struct.error, IndexError):
        return ""


# ── BagMRU tree walker ───────────────────────────────────────────────────────

def _read_mrulistex(key) -> list[int]:
    try:
        val = key.value("MRUListEx")
        data = val.raw_data()
        count = len(data) // 4
        order = []
        for i in range(count):
            n = struct.unpack_from("<I", data, i * 4)[0]
            if n == 0xFFFFFFFF:
                break
            order.append(n)
        return order
    except Exception:
        return []


def _walk_bagmru(key, parent_path: str, records: list, username: str, source_file: str):
    last_write = _regtime_to_utc(key.timestamp())

    # The shell item blob for each subkey is stored in the *parent* key
    # as a value whose name matches the subkey's name (a numeric string)
    parent_values = {v.name(): v.raw_data() for v in key.values() if v.name() != "MRUListEx"}

    for subkey in key.subkeys():
        try:
            slot_name = subkey.name()
            raw = parent_values.get(slot_name)

            if raw and len(raw) >= 4:
                # Shell item list: each item prefixed with 2-byte size; skip the list wrapper
                # BagMRU values store a single shell item (not a full IDList)
                item_size = struct.unpack_from("<H", raw, 0)[0]
                if item_size >= 4 and item_size <= len(raw):
                    item_data = raw[:item_size]
                    parsed = _parse_shell_item(item_data)
                else:
                    parsed = _parse_shell_item(raw)

                name = parsed["name"] or slot_name
                # UNC paths (\\server\share) from Network-type child items already
                # contain the full server name. If the parent path already includes
                # that server, use Network\server\share directly to avoid doubling.
                if name.startswith("\\\\"):
                    path = f"Network\\{name[2:]}"
                else:
                    path = f"{parent_path}\\{name}" if parent_path else name

                records.append({
                    "last_write": last_write,
                    "modified": parsed["modified"],
                    "path": path,
                    "folder_name": name,
                    "type": parsed["type_desc"],
                    "username": username,
                    "source_file": source_file,
                })

                _walk_bagmru(subkey, path, records, username, source_file)
        except Exception:
            continue


def parse_hive(hive_path: Path, username: str) -> list[dict]:
    records = []
    try:
        reg = Registry.Registry(str(hive_path))
    except Exception as e:
        print(f"[!] Cannot open {hive_path}: {e}", file=sys.stderr)
        return records

    # UsrClass.dat path
    candidates = [
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "Software\\Microsoft\\Windows\\Shell\\BagMRU",
    ]

    for key_path in candidates:
        try:
            root_key = reg.open(key_path)
            _walk_bagmru(root_key, "", records, username, str(hive_path))
            break
        except Exception:
            continue

    return records


# ── File discovery ───────────────────────────────────────────────────────────

def collect_hives(target: Path) -> list[tuple[Path, str]]:
    """Returns list of (hive_path, username) tuples."""
    if target.is_file():
        # Walk up the path looking for the last "Users" directory to extract the username.
        # Search from the right to find the Windows Users folder, not a Mac home path.
        parts = target.parts
        username = target.stem
        for i in range(len(parts) - 1, 0, -1):
            if parts[i].lower() == "users" and i + 1 < len(parts):
                candidate = parts[i + 1]
                # Skip Mac-style home directories sitting above the KAPE output
                if candidate.lower() not in ("stuartbird", "users", "local", "appdata", "microsoft", "windows"):
                    username = candidate
                    break
        return [(target, username)]

    results = []
    target_parts = target.parts
    for root, dirs, files in os.walk(target):
        rp = Path(root)
        for f in files:
            fl = f.lower()
            if fl in ("usrclass.dat", "ntuser.dat"):
                # Extract username from the path relative to the search root.
                # Walk up from the hive file to find the user folder, which sits
                # directly under a "Users" directory that is within our target tree.
                parts = rp.parts
                username = rp.name  # fallback
                for i in range(len(parts) - 1, 0, -1):
                    if parts[i].lower() == "users" and i >= len(target_parts) - 1:
                        if i + 1 < len(parts):
                            username = parts[i + 1]
                        break
                results.append((rp / f, username))
    return results


# ── Summary ──────────────────────────────────────────────────────────────────

def print_summary(records: list[dict], source: str):
    print(f"\n=== ShellBags Summary: {source} ===")
    print(f"Total entries       : {len(records)}")

    from collections import Counter
    by_user = Counter(r["username"] for r in records)
    print("\nEntries per user:")
    for user, count in by_user.most_common():
        print(f"  {user:<40} {count}")

    network = [r for r in records if "\\\\" in r["path"] or r["type"] == "Network"]
    if network:
        print(f"\nNetwork paths ({len(network)}):")
        for r in network:
            print(f"  [{r['username']}] {r['path']}")

    usb = [r for r in records if any(x in r["path"] for x in ("::{", "Removable", "USB"))]
    if usb:
        print(f"\nPotential removable media ({len(usb)}):")
        for r in usb:
            print(f"  [{r['username']}] {r['path']}")


# ── Main ─────────────────────────────────────────────────────────────────────

_FIELDNAMES = ["last_write", "modified", "path", "folder_name", "type", "username", "source_file"]


def main():
    ap = argparse.ArgumentParser(
        prog="shellbags_parse",
        description="Parse Windows ShellBag entries from UsrClass.dat or NTUSER.DAT.",
    )
    ap.add_argument("target", help="UsrClass.dat / NTUSER.DAT file, or Users directory")
    ap.add_argument("-o", "--output", required=True, help="Output CSV path")
    ap.add_argument("--summary", action="store_true", help="Print triage summary after parsing")
    args = ap.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"[!] Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    hives = collect_hives(target)
    if not hives:
        print("[!] No UsrClass.dat or NTUSER.DAT files found.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Found {len(hives)} hive(s). Parsing...")

    all_records = []
    for hive_path, username in hives:
        recs = parse_hive(hive_path, username)
        print(f"    {hive_path.name:<20} [{username}]  {len(recs)} entries")
        all_records.extend(recs)

    all_records.sort(key=lambda r: (r["username"], r["last_write"]))

    out = Path(args.output)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_FIELDNAMES)
        writer.writeheader()
        writer.writerows(all_records)

    print(f"[+] Written {len(all_records)} records to {out}")

    if args.summary:
        print_summary(all_records, str(target))


if __name__ == "__main__":
    main()
