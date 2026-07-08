# Intrinsic Timeline Viewer

A forensic timeline analysis toolkit for DFIR practitioners. Parse Windows forensic artefacts into structured CSV, then load and analyse them in a unified interactive viewer.

Built and maintained by [Intrinsic Security UK](https://intrinsicsecurityuk.com).

Tested on MacOS (Sequoia) and RHEL 10.

---

## Overview

The toolkit has two layers:

**Parsers** — command-line tools that extract artefacts from a KAPE or SANS triage collection and output structured CSV:

| Parser | Artefact | Source |
|--------|----------|--------|
| `evtx_parse.py` | Windows Event Logs | `.evtx` files |
| `mft_parse.py` | Master File Table | `$MFT` |
| `usn_parse.py` | USN Change Journal | `$J` |
| `reg_parse.py` | Registry hives | SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT |

**Intrinsic Timeline Viewer** (`timeline_viewer.py`) — a standalone PyQt6 GUI that loads any CSV output from the parsers (or any compatible CSV) and provides a unified analysis environment with filtering, searching, bookmarking, and export.

---

## Quick Start

```bash
# 1. Parse artefacts from a KAPE collection
python3 evtx_parse.py /kape/C/Windows/System32/winevt/Logs/ -o events.csv --summary
python3 mft_parse.py /kape/C/$MFT -o mft.csv --summary
python3 usn_parse.py /kape/C/$Extend/$J -o usn.csv --summary
python3 reg_parse.py /kape/C/Windows/System32/config/SYSTEM --hive system -o system.csv

# 2. Load into the viewer
python3 timeline_viewer.py events.csv
```

---

## Installation

### Requirements

Python 3.10 or later.

```bash
pip install python-evtx xmltodict PyYAML pandas PyQt6 mft python-registry
```

On systems where pip refuses to install to system packages:

```bash
pip install python-evtx xmltodict PyYAML pandas PyQt6 mft python-registry --break-system-packages
```

### Linux: additional system packages

On RHEL/Fedora if the viewer fails to start with an `xcb` error:

```bash
sudo dnf install libxcb xcb-util-wm xcb-util-image xcb-util-keysyms xcb-util-renderutil libxkbcommon-x11
```

---

## Intrinsic Timeline Viewer

### Usage

```bash
python3 timeline_viewer.py [file.csv]

# Options
--font-size PT     Font size in points (default: 12)
--scale FACTOR     UI scale factor for 4K displays (e.g. 1.75)
--dark             Force dark mode (useful on Linux)
```

### Workflow

1. Open a CSV via **File > Open CSV** or pass it as an argument.
2. Use the **column header filter inputs** to narrow by any field.
3. Use the **Search bar** for free-text search across key fields. Prefix with `NOT` to exclude: `NOT miiserver.exe`.
4. Use the **Query bar** for complex pandas expressions (see below).
5. Use the **date range row** to restrict to a time window (UTC).
6. **Bookmark rows** of interest with Space, then export via **File > Export bookmarked**.

### Filtering

**Column filters**: A filter input sits below each column label in the header. Type to filter that column. Event ID accepts comma-separated values for OR logic: `4624,4625`.

**Search bar**: Free-text search across event ID, description, computer, user SID, channel, provider, and event_data simultaneously.

**Date range**: From and To fields accept `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`. All times are UTC. Use the dropdown to select which timestamp column the range applies to.

**Pandas query bar**: Full pandas query syntax for complex filtering:

```python
# Explicit credential logons excluding known service accounts
event_id == "4648" and not event_data.str.contains("NT SERVICE")

# Multiple event IDs
event_id.isin(["4624", "4625", "4648"])

# MFT: deleted executables
extension == "exe" and is_deleted == "Yes"

# USN: file creation events
reason.str.contains("FILE_CREATE")
```

All filters combine with AND logic. The pandas query applies on top of all other filters.

**Category filter buttons** (bottom-right legend panel, EVTX data only): click to show only rows in that category.

### Bookmarking

Build a focused subset of rows from across the full dataset:

| Action | Result |
|--------|--------|
| Space | Toggle bookmark on current row, advance to next |
| Shift+Space | Bookmark all rows from anchor to current row |
| Shift+Click | Bookmark all rows from anchor to clicked row |
| ☆ Only | Show bookmarked rows only |
| Clear ☆ | Clear all bookmarks |
| File > Export bookmarked | Export bookmarked rows to CSV |

### Colour Coding (EVTX data)

| Colour | Category | Events |
|--------|----------|--------|
| Red | Critical: log cleared or tampered | 1102, 104 |
| Orange | High: persistence, privilege, policy change | 7045, 4720, 4698, 4719 |
| Yellow | Notable: review required | 4648, 4625, 4771, 4740 |
| Light blue | Logon: successful logon / special privileges | 4624, 4672 |
| Pale blue | Logoff: session ended | 4634 |

Colour coding indicates event categories that warrant attention. It does not assert that any individual record is malicious.

### Display on Linux / RHEL

The viewer requires a desktop session. It cannot be launched over a plain SSH connection without X forwarding:

```bash
ssh -X user@host
python3 ~/linux-forensic-tools/timeline_viewer.py events.csv
```

For 4K displays, use `--scale 1.75` to prevent the UI rendering at physical pixels.

---

## Parsers

### evtx_parse.py — Windows Event Logs

```bash
# Single file
python3 evtx_parse.py Security.evtx -o security.csv

# Directory (recursive)
python3 evtx_parse.py /kape/Logs/ -o events.csv --summary

# Filter to specific event IDs
python3 evtx_parse.py Security.evtx --filter-id 4624,4625,4648 -o logons.csv

# Filter to specific channels
python3 evtx_parse.py /kape/Logs/ --filter-channel Security,System -o filtered.csv
```

**Output schema**: `timestamp_utc`, `record_id`, `event_id`, `level`, `channel`, `provider`, `computer`, `user_sid`, `process_id`, `thread_id`, `description`, `event_data` (JSON), `source_file`

**Timestamp note**: Timestamps are always UTC. Windows Event Viewer displays local time — analysts in BST (UTC+1) will see timestamps one hour behind. This is correct behaviour, not a bug. Clock skew cannot be corrected automatically and requires corroboration from other sources.

**Triage summary** (`--summary`): record count and date range, computers and channels present, top 15 event IDs by frequency, watchlist hits (log cleared, new service, new user, scheduled task, audit policy change, WMI subscriptions, failed logon threshold, explicit credential logons).

---

### mft_parse.py — Master File Table

```bash
python3 mft_parse.py /kape/C/$MFT -o mft.csv --summary
```

**Output schema**: `si_created`, `si_modified`, `si_accessed`, `si_mft_modified`, `fn_created`, `fn_modified`, `fn_accessed`, `fn_mft_modified`, `entry_id`, `sequence`, `parent_ref`, `filename`, `extension`, `size`, `is_directory`, `is_deleted`, `flags`, `si_fn_discrepancy`, `source_file`

**Timestamp discrepancy**: The `si_fn_discrepancy` flag is set when SI timestamps differ from FN timestamps, which can indicate timestomping.

---

### usn_parse.py — USN Change Journal

```bash
python3 usn_parse.py /kape/C/$Extend/$J -o usn.csv --summary
```

**Output schema**: `timestamp_utc`, `file_ref`, `parent_ref`, `reason`, `filename`, `extension`, `attributes`, `source_file`

**Timestamp note**: All timestamps are UTC (converted from FILETIME).

---

### reg_parse.py — Registry Hives

```bash
# SAM — local user accounts
python3 reg_parse.py /kape/C/Windows/System32/config/SAM --hive sam -o sam.csv

# SYSTEM — computer name, timezone, services, USB devices
python3 reg_parse.py /kape/C/Windows/System32/config/SYSTEM --hive system -o system.csv

# SOFTWARE — installed applications, OS version, autoruns
python3 reg_parse.py /kape/C/Windows/System32/config/SOFTWARE --hive software -o software.csv

# SECURITY — cached domain logon timestamps, audit policy
python3 reg_parse.py /kape/C/Windows/System32/config/SECURITY --hive security -o security.csv

# NTUSER.DAT — user activity: UserAssist, RecentDocs, RunMRU, autoruns
python3 reg_parse.py /kape/C/Users/username/NTUSER.DAT --hive ntuser -o ntuser.csv
```

**Common output schema**: `timestamp`, `hive`, `artefact`, `name`, `value`, `details`, `key_path`, `source_file`

**Cached domain credentials**: The SECURITY hive contains up to 10 cached domain logon slots (NL$1–NL$10). Usernames are encrypted with the NL$KM key and cannot be recovered without the SYSTEM hive. Use impacket secretsdump for full extraction:

```bash
python3 secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

---

## Adding Event Maps

Maps are YAML files in the `maps/` directory that provide human-readable descriptions for event IDs:

```yaml
events:
  - provider: microsoft-windows-security-auditing
    event_id: 4624
    description: "Successful logon"
```

The `provider` value must match the provider name in the EVTX file, lowercased. Check the `provider` column in parser output to find the correct string for any unmapped events.

---

## Acknowledgements

The concept for this toolkit was directly inspired by Eric Zimmerman's forensic tools, in particular [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) and the broader EZ Tools suite. Zimmerman's work has set the standard for Windows forensic tooling and made modern DFIR practice significantly more accessible. This toolkit exists to bring equivalent capability to Linux and macOS analysis environments.

---

## Known Limitations

- The viewer is a single-user desktop application. It is not designed for server deployment.
- Tooltips on event_data cells are inconsistent on Linux at 4K resolution. Use the detail panel for full content.
- E01 image support requires `ewfmount` and appropriate mount permissions. Mount the image first, then point parsers at the mounted filesystem.
- USN Journal parsing handles sparse files. Very large journals may take several minutes to parse.
- Registry hive parsing requires the `python-registry` library. Heavily fragmented or corrupt hives may produce partial output.
