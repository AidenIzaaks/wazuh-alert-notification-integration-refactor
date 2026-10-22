#!/usr/bin/env python3
"""Dry-run or replay Wazuh JSON alerts through an existing custom integration.

No Wazuh configuration or alert files are modified. By default, this only
previews matching alerts; --execute is required to invoke the integration.

Examples:
  sudo python3 replay_wazuh_integration.py \
    --start '2026-10-20T09:00:00+02:00' \
    --end '2026-10-20T10:00:00+02:00' \
    --integration /var/ossec/integrations/custom-notifications \
    --min-level 6

  sudo python3 replay_wazuh_integration.py ... --execute --limit 5

Requires Python 3.8+ and the original integration script's dependencies.
"""

import argparse
import gzip
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path


def timestamp_arg(raw):
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid ISO-8601 timestamp: {raw}") from exc
    if value.tzinfo is None or value.utcoffset() is None:
        raise argparse.ArgumentTypeError(
            "Timestamps must include their UTC offset (e.g. +02:00 or Z)"
        )
    return value


def source_files(directory):
    # Wazuh retains live alerts.json and may rotate historical *.json.gz files.
    result = [
        p
        for p in directory.rglob("*")
        if p.is_file() and (p.name.endswith(".json") or p.name.endswith(".json.gz"))
    ]
    # Rotated files first; the active alerts.json last.
    return sorted(result, key=lambda p: (p.name == "alerts.json", str(p)))


def alert_rows(paths):
    for path in paths:
        opener = gzip.open if path.name.endswith(".gz") else open
        try:
            with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
                for line_number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    try:
                        alert = json.loads(line)
                    except json.JSONDecodeError:
                        print(
                            f"[WARN] Invalid JSON in {path}:{line_number}",
                            file=sys.stderr,
                        )
                        continue
                    if isinstance(alert, dict):
                        yield alert
        except (OSError, EOFError) as exc:
            print(f"[WARN] Failed reading {path}: {exc}", file=sys.stderr)


def alert_key(alert, integration):
    event_id = alert.get("id")
    if event_id:
        return f"{integration.resolve()}::{event_id}"
    # Some custom alerts lack IDs: deduplicate exact JSON content in that case.
    digest = hashlib.sha256(json.dumps(alert, sort_keys=True).encode()).hexdigest()
    return f"{integration.resolve()}::sha256:{digest}"


def load_completed(path):
    complete = set()
    if not path.exists():
        return complete
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                try:
                    complete.add(json.loads(line)["key"])
                except (ValueError, KeyError):
                    print(f"[WARN] Invalid state entry in {path}", file=sys.stderr)
    return complete


def invoke(integration, alert, api_key, hook_url, timeout):
    # Recreate integratord's conventional argv[1..3] calling convention.
    filename = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="wazuh-replay-",
            suffix=".alert",
            dir="/tmp",
            delete=False,
        ) as handle:
            filename = handle.name
            json.dump(alert, handle, ensure_ascii=False)
            handle.write("\n")
        completed = subprocess.run(
            [str(integration), filename, api_key, hook_url],
            cwd=str(integration.parent),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stderr[-1200:]
    finally:
        if filename is not None:
            Path(filename).unlink(missing_ok=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--start",
        type=timestamp_arg,
        required=True,
        help="Inclusive ISO-8601 start, with time-zone offset",
    )
    p.add_argument(
        "--end",
        type=timestamp_arg,
        required=True,
        help="Exclusive ISO-8601 end, with time-zone offset",
    )
    p.add_argument(
        "--integration",
        required=True,
        type=Path,
        help="Executable custom-* integration entrypoint",
    )
    p.add_argument("--alerts-dir", type=Path, default=Path("/var/ossec/logs/alerts"))
    p.add_argument(
        "--min-level", type=int, help="Mirror the integration <level> filter"
    )
    p.add_argument(
        "--group",
        action="append",
        default=[],
        help="Only alerts with this rule group; can repeat or use commas",
    )
    p.add_argument(
        "--rule-id",
        action="append",
        default=[],
        help="Only these Wazuh rule IDs; can repeat or use commas",
    )
    p.add_argument(
        "--execute",
        action="store_true",
        help="Actually call integration (default is dry run)",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit replayed alerts; useful for safe testing (0=all)",
    )
    p.add_argument(
        "--delay",
        type=float,
        default=0.2,
        help="Seconds between sends to avoid notification bursts",
    )
    p.add_argument(
        "--timeout", type=float, default=60, help="Per-invocation timeout in seconds"
    )
    p.add_argument(
        "--state-file",
        type=Path,
        default=Path("/var/tmp/wazuh-integration-replay.done.jsonl"),
        help="Replay IDs with zero-exit-code invocations; supports resume",
    )
    p.add_argument(
        "--api-key-env",
        default="WAZUH_REPLAY_API_KEY",
        help="Environment variable with api_key, if required",
    )
    p.add_argument(
        "--hook-url-env",
        default="WAZUH_REPLAY_HOOK_URL",
        help="Environment variable with hook_url, if required",
    )
    args = p.parse_args()

    if args.start >= args.end:
        p.error("--start must be before --end")
    if args.limit < 0 or args.delay < 0 or args.timeout <= 0:
        p.error("--limit and --delay must be >= 0 and --timeout must be > 0")
    if not args.alerts_dir.is_dir():
        p.error(f"Alerts directory not found: {args.alerts_dir}")
    if not args.integration.is_file():
        p.error(f"Integration entrypoint not found: {args.integration}")
    if args.execute and not os.access(args.integration, os.X_OK):
        p.error(f"Integration entrypoint not executable: {args.integration}")

    groups = {x.strip() for value in args.group for x in value.split(",") if x.strip()}
    rules = {x.strip() for value in args.rule_id for x in value.split(",") if x.strip()}
    completed = load_completed(args.state_file)
    seen = set()
    paths = source_files(args.alerts_dir)
    if not paths:
        p.error(f"No *.json or *.json.gz files found under {args.alerts_dir}")

    print(f"Mode: {'EXECUTE' if args.execute else 'DRY RUN (nothing will be sent)'}")
    print(
        f"Sources: {len(paths)} file(s)  |  Window: [{args.start.isoformat()}, {args.end.isoformat()})"
    )
    print(
        f"Filters: level>={args.min_level}, group={sorted(groups)}, rule={sorted(rules)}"
    )
    print(
        "NOTE: Match any <integration> level/group/rule_id/event_location filters manually."
    )
    print(
        "NOTE: State only knows about prior REPLAY successes, not past Wazuh deliveries."
    )

    count, already_done, sent, failures = 0, 0, 0, 0
    api_key = os.environ.get(args.api_key_env, "")
    hook_url = os.environ.get(args.hook_url_env, "")
    state_handle = None
    try:
        for alert in alert_rows(paths):
            try:
                event_time = datetime.fromisoformat(
                    str(alert["timestamp"]).replace("Z", "+00:00")
                )
                if event_time.tzinfo is None or event_time.utcoffset() is None:
                    continue
            except (ValueError, TypeError, KeyError):
                continue
            if not (args.start <= event_time < args.end):
                continue

            rule = alert.get("rule") or {}
            try:
                if (
                    args.min_level is not None
                    and int(rule.get("level", -1)) < args.min_level
                ):
                    continue
            except (ValueError, TypeError):
                continue
            if groups and not groups.intersection(rule.get("groups") or []):
                continue
            if rules and str(rule.get("id")) not in rules:
                continue

            key = alert_key(alert, args.integration)
            if key in seen:
                continue
            seen.add(key)
            if key in completed:
                already_done += 1
                continue
            if args.execute and args.limit and sent >= args.limit:
                break
            count += 1
            if not args.execute:
                if count <= 5:
                    print(
                        f"  preview {count}: {alert.get('timestamp')} id={alert.get('id')} "
                        f"rule={rule.get('id')} level={rule.get('level')}"
                    )
                continue

            try:
                code, error = invoke(
                    args.integration, alert, api_key, hook_url, args.timeout
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                code, error = 1, str(exc)
            if code != 0:
                failures += 1
                print(
                    f"[ERROR] Failed on alert id={alert.get('id')}: {error or f'exit status {code}'}",
                    file=sys.stderr,
                )
                print(
                    "[ERROR] Stopping, so the failure can be investigated.",
                    file=sys.stderr,
                )
                break
            if state_handle is None:
                args.state_file.parent.mkdir(parents=True, exist_ok=True)
                state_handle = args.state_file.open("a", encoding="utf-8")
            state_handle.write(
                json.dumps({"key": key, "timestamp": alert.get("timestamp")}) + "\n"
            )
            state_handle.flush()
            os.fsync(state_handle.fileno())
            completed.add(key)
            sent += 1
            if sent <= 5 or sent % 100 == 0:
                print(
                    f"[OK] Sent #{sent}: id={alert.get('id')} timestamp={alert.get('timestamp')}"
                )
            if args.delay:
                time.sleep(args.delay)
    except KeyboardInterrupt:
        print(
            "\n[WARN] Interrupted; successfully replayed IDs were saved to state.",
            file=sys.stderr,
        )
        failures += 1
    finally:
        if state_handle is not None:
            state_handle.close()
    print(
        f"Result: eligible={count}, previously_replayed={already_done}, "
        f"sent={sent}, failures={failures}"
    )
    if not args.execute:
        print("Nothing was sent. Add --execute to run the integration.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
