#!/usr/bin/env python3
"""
tasks_parse.py - Parse Windows Scheduled Task XML files.

Accepts a single .xml task file or a directory (recurses into subdirectories).
Outputs structured CSV compatible with the Intrinsic Timeline Viewer.

Usage:
    python3 tasks_parse.py /kape/C/Windows/System32/Tasks/ -o tasks.csv
    python3 tasks_parse.py /kape/C/Windows/System32/Tasks/ -o tasks.csv --summary
"""

import argparse
import csv
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


# Windows Task Scheduler XML namespace
_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def _tag(name: str) -> str:
    return f"{{{_NS}}}{name}"


def _find_text(element, *path) -> str:
    node = element
    for part in path:
        if node is None:
            return ""
        node = node.find(_tag(part))
    return (node.text or "").strip() if node is not None else ""


def _parse_triggers(task_element) -> str:
    triggers_el = task_element.find(_tag("Triggers"))
    if triggers_el is None:
        return ""
    parts = []
    for trigger in triggers_el:
        tag = trigger.tag.replace(f"{{{_NS}}}", "")
        start = _find_text(trigger, "StartBoundary")
        enabled = _find_text(trigger, "Enabled")
        desc = tag
        if start:
            desc += f" @ {start}"
        if enabled and enabled.lower() == "false":
            desc += " [disabled]"
        # CalendarTrigger schedule details
        schedule = trigger.find(_tag("ScheduleByDay"))
        if schedule is not None:
            interval = _find_text(schedule, "DaysInterval")
            if interval:
                desc += f" every {interval}d"
        schedule = trigger.find(_tag("ScheduleByWeek"))
        if schedule is not None:
            days = schedule.find(_tag("DaysOfWeek"))
            if days is not None:
                day_names = [d.tag.replace(f"{{{_NS}}}", "") for d in days]
                desc += f" on {','.join(day_names)}"
        parts.append(desc)
    return "; ".join(parts)


def _parse_actions(task_element) -> tuple[str, str]:
    actions_el = task_element.find(_tag("Actions"))
    if actions_el is None:
        return "", ""
    commands = []
    args_list = []
    for exec_el in actions_el.findall(_tag("Exec")):
        cmd = _find_text(exec_el, "Command")
        args = _find_text(exec_el, "Arguments")
        if cmd:
            commands.append(cmd)
        if args:
            args_list.append(args)
    # COM handler actions
    for com_el in actions_el.findall(_tag("ComHandler")):
        clsid = _find_text(com_el, "ClassId")
        if clsid:
            commands.append(f"[COM] {clsid}")
    return "; ".join(commands), "; ".join(args_list)


def parse_task_file(path: Path) -> dict | None:
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        print(f"[!] XML parse error in {path}: {e}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"[!] Cannot read {path}: {e}", file=sys.stderr)
        return None

    root = tree.getroot()

    # Handle files with and without namespace declaration
    if root.tag == _tag("Task"):
        task = root
    elif root.tag == "Task":
        # No namespace — reparse with empty prefix
        task = root
        global _NS
        _NS = ""
    else:
        return None

    reg = task.find(_tag("RegistrationInfo"))
    principals = task.find(_tag("Principals"))
    settings = task.find(_tag("Settings"))

    author = _find_text(reg, "Author") if reg is not None else ""
    date_created = _find_text(reg, "Date") if reg is not None else ""
    description = _find_text(reg, "Description") if reg is not None else ""
    uri = _find_text(reg, "URI") if reg is not None else ""

    run_as = ""
    logon_type = ""
    if principals is not None:
        principal = principals.find(_tag("Principal"))
        if principal is not None:
            run_as = _find_text(principal, "UserId") or _find_text(principal, "GroupId")
            logon_type = _find_text(principal, "LogonType")

    enabled = ""
    if settings is not None:
        enabled = _find_text(settings, "Enabled")

    command, arguments = _parse_actions(task)
    triggers = _parse_triggers(task)

    task_name = uri.lstrip("\\") if uri else path.stem

    return {
        "date_created": date_created,
        "task_name": task_name,
        "author": author,
        "run_as": run_as,
        "logon_type": logon_type,
        "enabled": enabled,
        "command": command,
        "arguments": arguments,
        "triggers": triggers,
        "description": description,
        "source_file": str(path),
    }


def collect_task_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    found = []
    for root, dirs, files in os.walk(target):
        for f in files:
            fp = Path(root) / f
            # Task files have no extension; skip obvious non-task files
            if fp.suffix.lower() in (".log", ".csv", ".txt", ".json", ".py"):
                continue
            found.append(fp)
    return sorted(found)


def print_summary(records: list[dict], source: str):
    print(f"\n=== Scheduled Tasks Summary: {source} ===")
    print(f"Total tasks         : {len(records)}")

    enabled = [r for r in records if r["enabled"].lower() == "true"]
    disabled = [r for r in records if r["enabled"].lower() == "false"]
    print(f"Enabled             : {len(enabled)}")
    print(f"Disabled            : {len(disabled)}")

    system_accounts = {"system", "s-1-5-18", "s-1-5-19", "s-1-5-20", "nt authority\\system",
                       "nt authority\\local service", "nt authority\\network service"}
    user_tasks = [r for r in records if r["run_as"].lower() not in system_accounts and r["run_as"]]
    if user_tasks:
        print(f"\nTasks running as non-system accounts ({len(user_tasks)}):")
        for r in user_tasks:
            print(f"  {r['task_name']:<50} {r['run_as']}")

    scripting = [r for r in records if any(
        x in r["command"].lower() for x in ("powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32")
    )]
    if scripting:
        print(f"\nTasks using scripting interpreters ({len(scripting)}):")
        for r in scripting:
            print(f"  {r['task_name']:<50} {r['command']}")

    no_author = [r for r in records if not r["author"]]
    if no_author:
        print(f"\nTasks with no registered author ({len(no_author)}):")
        for r in no_author:
            print(f"  {r['task_name']}")


_FIELDNAMES = [
    "date_created", "task_name", "author", "run_as", "logon_type",
    "enabled", "command", "arguments", "triggers", "description", "source_file",
]


def main():
    ap = argparse.ArgumentParser(
        prog="tasks_parse",
        description="Parse Windows Scheduled Task XML files.",
    )
    ap.add_argument("target", help="Task XML file or Tasks directory (e.g. C\\Windows\\System32\\Tasks\\)")
    ap.add_argument("-o", "--output", required=True, help="Output CSV path")
    ap.add_argument("--summary", action="store_true", help="Print a triage summary after parsing")
    args = ap.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"[!] Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    task_files = collect_task_files(target)
    if not task_files:
        print("[!] No task files found.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Found {len(task_files)} file(s). Parsing...")

    records = []
    errors = 0
    for f in task_files:
        rec = parse_task_file(f)
        if rec:
            records.append(rec)
        else:
            errors += 1

    records.sort(key=lambda r: r["date_created"] or "")

    out = Path(args.output)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_FIELDNAMES)
        writer.writeheader()
        writer.writerows(records)

    print(f"[+] Written {len(records)} records to {out}")
    if errors:
        print(f"[!] {errors} file(s) could not be parsed.")

    if args.summary:
        print_summary(records, str(target))


if __name__ == "__main__":
    main()
