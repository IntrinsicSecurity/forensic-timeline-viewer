# evtx-parse: Build and Deployment Guide

## Overview

Two tools:

- `evtx_parse.py` - Command-line EVTX parser. Produces structured CSV from Windows Event Log files.
- `timeline_viewer.py` - Standalone GUI timeline viewer. Loads CSV output from evtx_parse or any compatible CSV.

Tested on macOS (Sequoia) and RHEL 10.

---

## Prerequisites

### Python

Python 3.10 or later required.

```bash
python3 --version
```

### Dependencies

```bash
pip install python-evtx xmltodict PyYAML pandas PyQt6
```

On systems where pip refuses to install to system packages:

```bash
pip install python-evtx xmltodict PyYAML pandas PyQt6 --break-system-packages
```

### Linux: additional system packages

On RHEL/Fedora if PyQt6 fails to start with an xcb error:

```bash
sudo dnf install libxcb xcb-util-wm xcb-util-image xcb-util-keysyms xcb-util-renderutil libxkbcommon-x11
```

---

## File Structure

```
evtx-parse/
  evtx_parse.py          Parser
  timeline_viewer.py     GUI viewer
  requirements.txt       Python dependencies
  maps/                  Event description maps
    security.yaml        Security log events
    system.yaml          System log events (services, WMI, Defender)
    powershell.yaml      PowerShell and WinRM events
    sysmon.yaml          Sysmon events 1-29
    taskscheduler.yaml   Task Scheduler events
    rdp.yaml             RDP session events
```

---

## evtx_parse.py

### Usage

```bash
# Single file
python3 evtx_parse.py Security.evtx -o security.csv

# Directory (recursive - finds all .evtx files)
python3 evtx_parse.py /path/to/logs/ -o all_events.csv

# With triage summary
python3 evtx_parse.py /path/to/logs/ -o all_events.csv --summary

# Filter to specific event IDs only
python3 evtx_parse.py Security.evtx --filter-id 4624,4625,4648 -o logons.csv

# Filter to specific channels
python3 evtx_parse.py /path/to/logs/ --filter-channel Security,System -o filtered.csv

# Custom maps directory
python3 evtx_parse.py Security.evtx --maps-dir /path/to/maps/ -o output.csv

# Quiet mode (no progress output)
python3 evtx_parse.py Security.evtx -o output.csv -q
```

### Output Schema

Fixed 13-column CSV:

| Column | Description |
|--------|-------------|
| timestamp_utc | Event timestamp in UTC |
| record_id | Event record number |
| event_id | Windows Event ID |
| level | Information / Warning / Error / Critical |
| channel | Log channel (Security, System, etc.) |
| provider | Event provider name |
| computer | Source computer hostname |
| user_sid | Subject user SID |
| process_id | Process ID (decimal) |
| thread_id | Thread ID (decimal) |
| description | Human-readable event description (from maps) |
| event_data | JSON blob of all event-specific fields |
| source_file | Source .evtx filename |

### Timestamp Note

EVTX timestamps are stored in UTC and returned as UTC by the parser. Windows Event Viewer displays timestamps in local time, which can cause confusion. The timestamps in CSV output are always UTC regardless of the timezone of the source system. Analysts working on logs from systems in BST (UTC+1) will see timestamps one hour behind the user's local experience. This is correct behaviour.

If the source system clock was incorrect at the time of collection, timestamps will be UTC but inaccurate. Clock skew cannot be corrected automatically and requires corroboration from network logs or other sources.

### E01 Image Support

Mount the image first, then point the parser at the Logs directory:

```bash
ewfmount image.E01 /mnt/ewf
mount -r /mnt/ewf/ewf1 /mnt/image
python3 evtx_parse.py /mnt/image/Windows/System32/winevt/Logs/ -o output.csv --summary
```

### KAPE Collection

Point at the Logs directory within the KAPE output:

```bash
python3 evtx_parse.py /path/to/kape/C/Windows/System32/winevt/Logs/ -o output.csv --summary
```

### Triage Summary

The `--summary` flag prints to stderr after parsing:

- Total record count and date range
- Computers and channels present
- Top 15 event IDs by frequency
- Watchlist hits: log cleared, new service, new user, scheduled task creation, audit policy change, WMI subscriptions, failed logon threshold, explicit credential logons

---

## timeline_viewer.py

### Usage

```bash
# Basic
python3 timeline_viewer.py output.csv

# With font size override
python3 timeline_viewer.py output.csv --font-size 14

# With UI scale factor (for 4K displays)
python3 timeline_viewer.py output.csv --scale 1.75

# Combined
python3 timeline_viewer.py output.csv --scale 1.75 --font-size 13
```

### Display on RHEL / Linux

The viewer requires a desktop session. It cannot be launched over a plain SSH connection without X forwarding.

To launch over SSH with the window appearing on your local machine:

```bash
ssh -X user@host
python3 ~/evtx-parse/timeline_viewer.py ~/output.csv --scale 1.75
```

### 4K Displays

Use `--scale 1.75` (or adjust to preference). Without it, the UI renders at physical pixels and is unreadable at 3840x2160.

### Filtering

**Column filters** (filter row below toolbar): Event ID, Computer, Channel, User SID, Description, Source File. Event ID accepts comma-separated values for OR logic: `4624,4625`.

**Global search bar**: Free-text search across event ID, description, computer, user SID, channel, provider, and event_data simultaneously. Prefix with `NOT` to exclude: `NOT miiserver.exe`.

**Date range**: From and To fields accept `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`. All times are UTC.

**Pandas query bar**: Full pandas query syntax for complex filtering:

```python
# All explicit credential logons excluding known service accounts
event_id == "4648" and not event_data.str.contains("miiserver") and not event_data.str.contains("NT SERVICE")

# Failed logons from a specific workstation
event_id == "4625" and computer.str.contains("WORKSTATION01")

# Multiple event IDs
event_id.isin(["4624", "4625"]) and not event_data.str.contains("miiserver")
```

All filters combine with AND logic. The pandas query applies on top of column filters and search.

**Category filter buttons** (bottom-right legend panel): Click to show only rows in that category. Click again to clear.

### Colour Coding

| Colour | Category | Example Events |
|--------|----------|----------------|
| Red | Critical: log cleared or tampered | 1102, 104 |
| Orange | High: persistence, privilege, policy change | 7045, 4720, 4698, 4719 |
| Yellow | Notable: review required | 4648, 4625, 4771, 4740 |
| Light blue | Logon: successful logon, special privileges | 4624, 4672 |
| Pale blue | Logoff: session ended | 4634 |
| White | All other events | - |

Colour coding indicates event categories that warrant attention. It does not assert that any individual record is malicious. Analyst judgement is required in all cases.

### Event Detail Panel

Click any row to populate the detail panel at the bottom of the window. All fields are shown with event_data JSON expanded as key-value pairs.

### Fit Columns Button

After loading a file, click Fit Columns in the toolbar to auto-size all columns to their content. Columns remain manually resizable after fitting.

---

## Adding Event Maps

Maps are YAML files in the `maps/` directory. Each file can cover one or more providers.

```yaml
events:
  - provider: microsoft-windows-security-auditing
    event_id: 4624
    description: "Successful logon"
```

The `provider` value must match the provider name in the EVTX file, lowercased. Run the parser and check the `provider` column in the output CSV to find the correct value for any unmapped events.

---

## Known Limitations

- Tooltips on event_data cells are inconsistent on Linux at 4K resolution. Use the detail panel for full event_data content.
- E01 image support requires `ewfmount` and appropriate mount permissions.
- The viewer is a single-user desktop application. It is not designed for server deployment.
