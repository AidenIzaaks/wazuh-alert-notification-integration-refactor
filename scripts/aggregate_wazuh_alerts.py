#!/usr/bin/env python3
"""Summarize historical Wazuh JSON alerts by rule ID, with optional CSV/JSON exports.

Reads current alerts.json and rotated *.json.gz files. Does not change alert
files or send notifications. Time range is [start, end), using ISO-8601 with
an explicit UTC offset. Supports the same time, severity, group, and rule
filters as replay_wazuh_integration.py.

Example:
    sudo python3 aggregate_wazuh_alerts.py \
      --start '2026-10-20T09:00:00+02:00' \
      --end '2026-10-20T10:00:00+02:00' \
      --min-level 6 \
      --csv-out /tmp/wazuh-rule-summary.csv \
      --json-out /tmp/wazuh-rule-summary.json
"""

import argparse
import csv
import gzip
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


def parse_datetime(value):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None or dt.utcoffset() is None:
            raise ValueError("Missing UTC offset")
        return dt
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid ISO-8601 datetime {value!r}; include timezone (e.g. +02:00 or Z)"
        ) from exc


def list_sources(directory):
    """Read actual alert JSON files, not similarly named .log/.sum files."""
    return sorted(
        (
            p
            for p in directory.rglob("*")
            if p.is_file() and (p.name.endswith(".json") or p.name.endswith(".json.gz"))
        ),
        key=lambda p: (p.name == "alerts.json", str(p)),
    )


def iter_alerts(paths, stats):
    for path in paths:
        opener = gzip.open if path.name.endswith(".gz") else open
        try:
            with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
                for number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    stats["lines_scanned"] += 1
                    try:
                        data = json.loads(line)
                        if not isinstance(data, dict):
                            raise ValueError("Expected JSON object")
                    except (ValueError, json.JSONDecodeError):
                        stats["invalid_json"] += 1
                        print(
                            f"[WARN] Ignoring invalid JSON at {path}:{number}",
                            file=sys.stderr,
                        )
                        continue
                    yield data
        except (OSError, EOFError) as exc:
            stats["file_errors"] += 1
            print(f"[WARN] Could not read {path}: {exc}", file=sys.stderr)


def values_from_flags(items):
    return {s.strip() for item in items for s in item.split(",") if s.strip()}


def agent_label(alert):
    agent = alert.get("agent") or {}
    if not isinstance(agent, dict):
        return "unknown"
    name = str(agent.get("name") or "unknown")
    agent_id = agent.get("id")
    return f"{name} ({agent_id})" if agent_id is not None else name


def timestamp_or_none(alert):
    try:
        return parse_datetime(alert.get("timestamp"))
    except argparse.ArgumentTypeError:
        return None


def matching_alerts(paths, args, stats):
    rule_ids = values_from_flags(args.rule_id)
    groups = values_from_flags(args.group)
    seen = set()

    for alert in iter_alerts(paths, stats):
        when = timestamp_or_none(alert)
        if when is None:
            stats["invalid_timestamp"] += 1
            continue
        if not (args.start <= when < args.end):
            continue
        rule = alert.get("rule") or {}
        if not isinstance(rule, dict):
            continue
        rule_id = rule.get("id")
        if rule_id is None:
            stats["missing_rule"] += 1
            continue
        try:
            level = int(rule.get("level", -1))
        except (ValueError, TypeError):
            level = -1
        if args.min_level is not None and level < args.min_level:
            continue
        if rule_ids and str(rule_id) not in rule_ids:
            continue
        rule_groups = rule.get("groups") or []
        if not isinstance(rule_groups, list):
            rule_groups = []
        if groups and not groups.intersection(map(str, rule_groups)):
            continue

        if not args.no_dedupe:
            event_id = alert.get("id")
            key = (
                str(event_id)
                if event_id is not None
                else "hash:"
                + hashlib.sha256(
                    json.dumps(alert, sort_keys=True, ensure_ascii=False).encode(
                        "utf-8"
                    )
                ).hexdigest()
            )
            if key in seen:
                stats["duplicates_skipped"] += 1
                continue
            seen.add(key)
        stats["matching_alerts"] += 1
        yield alert, rule, str(rule_id), level, when, rule_groups


def summarize(paths, args):
    stats = Counter()
    by_rule = {}
    for alert, rule, rule_id, level, when, groups in matching_alerts(
        paths, args, stats
    ):
        if rule_id not in by_rule:
            by_rule[rule_id] = {
                "rule_id": rule_id,
                "count": 0,
                "level": level,
                "first_seen": when,
                "last_seen": when,
                "descriptions": Counter(),
                "agents": Counter(),
                "groups": set(),
            }
        item = by_rule[rule_id]
        item["count"] += 1
        item["level"] = max(item["level"], level)
        item["first_seen"] = min(item["first_seen"], when)
        item["last_seen"] = max(item["last_seen"], when)
        item["descriptions"][str(rule.get("description") or "(no description)")] += 1
        item["agents"][agent_label(alert)] += 1
        item["groups"].update(map(str, groups))

    results = []
    for item in by_rule.values():
        agents = sorted(item["agents"].items(), key=lambda pair: (-pair[1], pair[0]))
        results.append(
            {
                "rule_id": item["rule_id"],
                "level": item["level"],
                "description": item["descriptions"].most_common(1)[0][0],
                "count": item["count"],
                "first_seen": item["first_seen"]
                .astimezone(args.start.tzinfo)
                .isoformat(timespec="seconds"),
                "last_seen": item["last_seen"]
                .astimezone(args.start.tzinfo)
                .isoformat(timespec="seconds"),
                "unique_agents": len(item["agents"]),
                "agents": [{"agent": name, "count": count} for name, count in agents],
                "groups": sorted(item["groups"]),
            }
        )
    results.sort(key=lambda item: (-item["count"], -item["level"], item["rule_id"]))
    return results, stats


def export_csv(path, results):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "rule_id",
                "level",
                "description",
                "count",
                "first_seen",
                "last_seen",
                "unique_agents",
                "agents",
                "groups",
            ],
        )
        writer.writeheader()
        for item in results:
            writer.writerow(
                {
                    **{k: v for k, v in item.items() if k not in {"agents", "groups"}},
                    "agents": "; ".join(
                        f"{x['agent']}: {x['count']}" for x in item["agents"]
                    ),
                    "groups": ", ".join(item["groups"]),
                }
            )


def print_summary(results, stats, args, num_files):
    print(
        f"Window (start inclusive, end exclusive): {args.start.isoformat()} to {args.end.isoformat()}"
    )
    print(
        f"Files scanned: {num_files} | Alerts matched: {stats['matching_alerts']} | "
        f"Unique rules: {len(results)} | Duplicate alerts skipped: {stats['duplicates_skipped']}"
    )
    print(
        f"Invalid JSON lines: {stats['invalid_json']} | "
        f"Invalid/missing timestamps: {stats['invalid_timestamp']} | "
        f"Unreadable files: {stats['file_errors']}"
    )
    if not results:
        print("No alerts matched the supplied filters.")
        return
    print("\nCount  Level  Rule ID    Agents  Description")
    print("-----  -----  ---------  ------  -----------")
    rows = results if args.top == 0 else results[: args.top]
    for item in rows:
        print(
            f"{item['count']:>5}  {item['level']:>5}  {item['rule_id']:<9}  "
            f"{item['unique_agents']:>6}  {item['description']}"
        )
    if len(rows) < len(results):
        print(
            f"... {len(results) - len(rows)} more rules omitted from terminal output "
            "(all included in exports)."
        )


def main(argv=None):
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "--start",
        required=True,
        type=parse_datetime,
        help="Inclusive ISO-8601 timestamp with explicit UTC offset",
    )
    p.add_argument(
        "--end",
        required=True,
        type=parse_datetime,
        help="Exclusive ISO-8601 timestamp with explicit UTC offset",
    )
    p.add_argument("--alerts-dir", type=Path, default=Path("/var/ossec/logs/alerts"))
    p.add_argument("--min-level", type=int, help="Minimum severity level, inclusive")
    p.add_argument(
        "--group",
        action="append",
        default=[],
        help="Only these rule groups (comma-separated or repeat flag)",
    )
    p.add_argument(
        "--rule-id",
        action="append",
        default=[],
        help="Only these rule IDs (comma-separated or repeat flag)",
    )
    p.add_argument("--csv-out", type=Path, help="Write all rule summaries to CSV")
    p.add_argument(
        "--json-out", type=Path, help="Write summary and per-agent counts to JSON"
    )
    p.add_argument(
        "--top",
        type=int,
        default=25,
        help="Number of rules to print in terminal (0 means all; default 25)",
    )
    p.add_argument(
        "--no-dedupe",
        action="store_true",
        help="Do not deduplicate matching alerts by Wazuh event id",
    )
    args = p.parse_args(argv)
    if args.start >= args.end:
        p.error("--start must be earlier than --end")
    if args.top < 0:
        p.error("--top cannot be negative")
    if not args.alerts_dir.is_dir():
        p.error(f"Alerts directory does not exist: {args.alerts_dir}")
    files = list_sources(args.alerts_dir)
    if not files:
        p.error(f"No .json or .json.gz alert files found in {args.alerts_dir}")

    results, stats = summarize(files, args)
    print_summary(results, stats, args, len(files))
    if args.csv_out:
        export_csv(args.csv_out, results)
        print(f"CSV saved to: {args.csv_out}")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "start": args.start.isoformat(),
            "end": args.end.isoformat(),
            "filters": {
                "min_level": args.min_level,
                "groups": sorted(values_from_flags(args.group)),
                "rule_ids": sorted(values_from_flags(args.rule_id)),
            },
            "stats": {"files_scanned": len(files), **dict(stats)},
            "rules": results,
        }
        args.json_out.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"JSON saved to: {args.json_out}")
    return 1 if stats["file_errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
