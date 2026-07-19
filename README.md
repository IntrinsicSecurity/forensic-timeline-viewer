# Intrinsic Timeline Viewer

A forensic timeline analysis toolkit for DFIR practitioners. Parse Windows forensic artefacts into structured CSV, then load and analyse them in a unified interactive viewer.

Built and maintained by [Intrinsic Security UK](https://intrinsicsecurityuk.com).

Tested on MacOS (Sequoia) and RHEL 10.

---

## Overview

The toolkit has two layers:

**Parsers** - command-line tools that extract artefacts from a KAPE or SANS triage collection and output structured CSV:

| Parser | Artefact | Source |
|--------|----------|--------|
| `evtx_parse.py` | Windows Event Logs | `.evtx` files |
| `mft_parse.py` | Master File Table | `$MFT` |
| `usn_parse.py` | USN Change Journal | `$J` |
| `reg_parse.py` | Registry hives | SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT |
| `recyclebin_parse.py` | Recycle Bin metadata | `$Recycle.Bin\<SID>\$I*` |
| `tasks_parse.py` | Scheduled Tasks | `C:\Windows\System32\Tasks\` |
| `shellbags_parse.py` | ShellBags (Explorer browsing history) | `UsrClass.dat`, `NTUSER.DAT` |
| `prefetch_parse.py` | Prefetch execution history | `C:\Windows\Prefetch\*.pf` |

**Intrinsic Timeline Viewer** (`timeline_viewer.py`) - a standalone PyQt6 GUI that loads any CSV output from the parsers (or any compatible CSV) and provides a unified analysis environment with filtering, searching, bookmarking, and export.

---

## Data Sources

The parsers are not limited to KAPE output. They will work against any accessible filesystem path:

- **KAPE or SANS triage collections**: point the parser at the collected artefact files directly.
- **Mounted forensic images**: mount a raw (dd), E01, or other supported image with `ewfmount`, `xmount`, or `Arsenal Image Mounter`, then point the parser at the mounted volume. No special flags needed.
- **Live host**: the parsers can be run directly on a live Windows host (via WSL or a mounted Python environment) or a live Linux/macOS host. Apply standard forensic caveats: running tools on a live system modifies timestamps and may alter evidence. Document all actions taken and prefer a triage collection where possible.

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

### Step 1: Clone the repository

```bash
git clone https://github.com/IntrinsicSecurity/forensic-timeline-viewer.git
cd forensic-timeline-viewer
```

If git is not installed:

- **macOS**: `xcode-select --install`
- **Ubuntu/Debian**: `sudo apt install git`
- **RHEL/Fedora**: `sudo dnf install git`

---

### Step 2: Check Python version

Python 3.10 or later is required:

```bash
python3 --version
```

If Python is not installed or is below 3.10, install it before continuing (see platform sections below).

---

### macOS

Install dependencies with pip:

```bash
pip install python-evtx xmltodict PyYAML pandas PyQt6 mft python-registry dissect.util
```

If pip refuses with a system packages error:

```bash
pip install python-evtx xmltodict PyYAML pandas PyQt6 mft python-registry dissect.util --break-system-packages
```

---

### Ubuntu / Debian

**Step 3: Install Python and pip**

Ubuntu 22.04 and later ship with Python 3.10+. Install pip and venv. On Ubuntu 24.04 the venv package is version-specific:

```bash
sudo apt update
sudo apt install python3-pip python3.12-venv
```

On older Ubuntu versions (22.04 and earlier), use `python3-venv` instead of `python3.12-venv`.

**Step 4: Install dependencies**

From Ubuntu 23.04 onwards, Ubuntu blocks pip from installing packages system-wide to prevent conflicts with its own package manager. The standard workaround is a virtual environment: an isolated folder that holds the Python packages for this toolkit, separate from the rest of the system.

Create the virtual environment once:

```bash
python3 -m venv ~/dfir-env
```

Activate it and install the dependencies:

```bash
source ~/dfir-env/bin/activate
pip install python-evtx xmltodict PyYAML pandas PyQt6 mft python-registry dissect.util
```

**Every time you open a new terminal**, activate the virtual environment before running any of the tools, otherwise Python will not find the installed packages:

```bash
source ~/dfir-env/bin/activate
```

Your prompt will show `(dfir-env)` at the start when the environment is active.

On Ubuntu 20.04 or 22.04, if you prefer not to use a virtual environment:

```bash
pip3 install python-evtx xmltodict PyYAML pandas PyQt6 mft python-registry dissect.util --break-system-packages
```

**Step 5: Install Qt6 libraries for the viewer**

This step installs system packages and has nothing to do with the virtual environment. Run it in a normal terminal (the venv does not need to be active):

```bash
sudo apt install libxcb-cursor0 libxcb-xinerama0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxkbcommon-x11-0
```

The viewer requires a desktop session. It cannot run over a plain SSH connection. If you are connecting remotely, either use a graphical remote desktop session, or parse artefacts on the remote host and copy the CSV to your local machine for viewing.

---

### RHEL / Fedora

**Step 3: Install Python and pip**

```bash
sudo dnf install python3 python3-pip
```

**Step 4: Install dependencies**

```bash
pip3 install python-evtx xmltodict PyYAML pandas PyQt6 mft python-registry dissect.util
```

**Step 5: Install Qt6 libraries for the viewer**

If the viewer fails to start with an `xcb` error:

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

For 4K displays, use `--scale 1.75` to prevent the UI rendering at physical pixels.

---

## Parsers

### evtx_parse.py - Windows Event Logs

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

**Timestamp note**: Timestamps are always UTC. Windows Event Viewer displays local time : analysts in BST (UTC+1) will see timestamps one hour behind. This is correct behaviour, not a bug. Clock skew cannot be corrected automatically and requires corroboration from other sources.

**Triage summary** (`--summary`): record count and date range, computers and channels present, top 15 event IDs by frequency, watchlist hits (log cleared, new service, new user, scheduled task, audit policy change, WMI subscriptions, failed logon threshold, explicit credential logons).

---

### mft_parse.py - Master File Table

```bash
python3 mft_parse.py /kape/C/$MFT -o mft.csv --summary
```

**Output schema**: `si_created`, `si_modified`, `si_accessed`, `si_mft_modified`, `fn_created`, `fn_modified`, `fn_accessed`, `fn_mft_modified`, `entry_id`, `sequence`, `parent_ref`, `filename`, `extension`, `size`, `is_directory`, `is_deleted`, `flags`, `si_fn_discrepancy`, `source_file`

**Timestamp discrepancy**: The `si_fn_discrepancy` flag is set when SI timestamps differ from FN timestamps, which can indicate timestomping.

---

### usn_parse.py - USN Change Journal

```bash
python3 usn_parse.py /kape/C/$Extend/$J -o usn.csv --summary
```

**Output schema**: `timestamp_utc`, `file_ref`, `parent_ref`, `reason`, `filename`, `extension`, `attributes`, `source_file`

**Timestamp note**: All timestamps are UTC (converted from FILETIME).

---

### reg_parse.py - Registry Hives

```bash
# SAM : local user accounts
python3 reg_parse.py /kape/C/Windows/System32/config/SAM --hive sam -o sam.csv

# SYSTEM : computer name, timezone, services, USB devices
python3 reg_parse.py /kape/C/Windows/System32/config/SYSTEM --hive system -o system.csv

# SOFTWARE : installed applications, OS version, autoruns
python3 reg_parse.py /kape/C/Windows/System32/config/SOFTWARE --hive software -o software.csv

# SECURITY : cached domain logon timestamps, audit policy
python3 reg_parse.py /kape/C/Windows/System32/config/SECURITY --hive security -o security.csv

# NTUSER.DAT : user activity: UserAssist, RecentDocs, RunMRU, autoruns
python3 reg_parse.py /kape/C/Users/username/NTUSER.DAT --hive ntuser -o ntuser.csv
```

**Common output schema**: `timestamp`, `hive`, `artefact`, `name`, `value`, `details`, `key_path`, `source_file`

**Shimcache** (`--hive system`): extracts AppCompatCache entries from the SYSTEM hive. Each entry records that an executable was present on the filesystem at the time Windows processed it : shimcache does not confirm execution. Entries are ordered 0 (most recently updated) to oldest. The `timestamp` field is the last-modified time of the executable file itself, not the time it was shimcached. Supports Windows 10 / Server 2016 / Server 2019 ("10ts" format) and Windows Vista / 7 ("BADC0FFE" format).

**Cached domain credentials**: The SECURITY hive contains up to 10 cached domain logon slots (NL$1–NL$10). Usernames are encrypted with the NL$KM key and cannot be recovered without the SYSTEM hive. Use impacket secretsdump for full extraction:

```bash
python3 secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

---

### recyclebin_parse.py - Recycle Bin

```bash
python3 recyclebin_parse.py /kape/C/'$Recycle.Bin'/ -o recyclebin.csv --summary
```

Accepts a single `$I` file or a directory. Recurses into SID subfolders automatically.

**Output schema**: `timestamp_utc`, `original_path`, `filename`, `extension`, `size_bytes`, `size_human`, `recycle_bin_file`, `source_dir`

**Note**: Only `$I` metadata files are parsed. `$R` files (the deleted file content) are ignored.

---

### tasks_parse.py - Scheduled Tasks

```bash
python3 tasks_parse.py /kape/C/Windows/System32/Tasks/ -o tasks.csv --summary
```

Accepts a single task XML file or the Tasks directory. Recurses into subdirectories.

**Output schema**: `date_created`, `task_name`, `author`, `run_as`, `logon_type`, `enabled`, `command`, `arguments`, `triggers`, `description`, `source_file`

**Triage summary** (`--summary`): flags tasks running under non-system accounts, tasks using scripting interpreters (PowerShell, cmd, wscript, cscript, mshta, rundll32, regsvr32), and tasks with no registered author.

**Note**: Tasks created programmatically via the Task Scheduler COM API may exist only in the registry (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`) and will not appear as XML files in the Tasks directory. Parse the SOFTWARE hive with `reg_parse.py` to recover these.

---

### shellbags_parse.py - ShellBags

```bash
# Single hive
python3 shellbags_parse.py /kape/C/Users/username/AppData/Local/Microsoft/Windows/UsrClass.dat -o shellbags.csv

# All users in a Users directory
python3 shellbags_parse.py /kape/C/Users/ -o shellbags.csv --summary
```

Accepts a single `UsrClass.dat` or `NTUSER.DAT` hive file, or a `Users` directory. When given a directory, it recurses to find all hive files and extracts the username from each hive's path automatically.

**Output schema**: `last_write`, `modified`, `path`, `folder_name`, `type`, `username`, `source_file`

- `last_write`: timestamp of the BagMRU registry key. Reflects the most recent Explorer browse activity at or below this folder.
- `modified`: last modified timestamp of the folder itself, extracted from the shell item (DOS date/time, not always populated).
- `path`: full reconstructed browsing path (e.g. `My Computer\C:\Users\username\Documents`).
- `type`: item type : `Root`, `Volume`, `Folder`, `File`, `Network`, `Control Panel`, `URI`.

**Triage summary** (`--summary`): total entry count per user, network paths, and potential removable media references.

**Where to find hives in a KAPE collection:**

| Hive | Path |
|------|------|
| `UsrClass.dat` | `C\Users\<username>\AppData\Local\Microsoft\Windows\` |
| `NTUSER.DAT` | `C\Users\<username>\` |

**Note**: ShellBags record Explorer browsing activity including folders that no longer exist, network shares, and paths on removed USB devices. The `last_write` timestamp on a BagMRU key reflects when the entry was last updated, not necessarily when the folder was first browsed. Timestamps in the shell item itself (the `modified` field) are DOS date/time pairs with 2-second resolution and may be empty for network and virtual items.

---

### prefetch_parse.py - Prefetch

```bash
# Single prefetch file
python3 prefetch_parse.py SVCHOST.EXE-39447866.pf -o prefetch.csv

# Directory of prefetch files
python3 prefetch_parse.py /kape/C/Windows/Prefetch/ -o prefetch.csv --summary

# Omit referenced files column (reduces CSV size)
python3 prefetch_parse.py /kape/C/Windows/Prefetch/ -o prefetch.csv --no-files
```

Requires `pip install dissect.util` for MAM-compressed prefetch files (Windows 10 and later). Uncompressed prefetch (Windows Vista/7) needs no additional dependencies.

**Output schema**: `timestamp`, `executable`, `hash`, `run_count`, `run_number`, `volume_path`, `volume_serial`, `files_loaded`, `referenced_files`, `source_file`

- `timestamp`: UTC execution time. One row is emitted per recorded run time, so a single prefetch file may produce up to 8 rows (Windows 10 stores the 8 most recent run times).
- `run_count`: total execution count stored in the prefetch file. This is a lifetime counter and will exceed 8.
- `run_number`: 1 = most recent run, 8 = oldest recorded run.
- `referenced_files`: pipe-separated list of files in the prefetch load order (DLLs and other modules loaded during execution). Use the detail panel in the viewer to read this field.
- `volume_path`: volume device path or GUID as recorded in the prefetch file (e.g. `\VOLUME{...}` or `\DEVICE\HARDDISKVOLUMEn`).

**Prefetch and execution evidence**: prefetch confirms that an executable ran, when it last ran (up to 8 timestamps), and which files it loaded. It does not record the user context, arguments, or process tree. For that, correlate with event 4688 (process creation), Sysmon event 1, or UserAssist.

**Supported versions**: Windows Vista/7 (format version 26) and Windows 8.1/10/11/Server 2016+ (versions 30 and 31). Windows XP (version 17) is not supported.

**Where to find prefetch files in a KAPE collection**: `C\Windows\Prefetch\*.pf`

**Note**: Prefetch must be enabled. It is enabled by default on desktop Windows but disabled by default on Windows Server. Confirm with the registry value `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher` (0 = disabled, 1 = application only, 3 = enabled).

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

## Comparison with Other Tools

For large-scale or team investigations, tools such as [log2timeline/Plaso](https://github.com/log2timeline/plaso) with [Timesketch](https://timesketch.org/) or an ELK stack may be more appropriate. Plaso parses a much wider range of artefacts in a single pass from a raw image or triage collection, and Timesketch provides collaborative analysis, tagging, and saved searches across a team. ELK is well suited to high-volume, log-heavy investigations.

This toolkit occupies a different space. It is designed for fast, standalone, single-case triage, particularly useful for:

- Sole practitioners or small teams without standing infrastructure
- Client-site work on an air-gapped or network-restricted forensic workstation
- Cases where getting results quickly matters more than broad artefact coverage
- Analysts who want direct control over what is parsed and how it is presented

It requires no server, no pipeline configuration, and no internet connection. Clone the repo, install dependencies, and parse.

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
