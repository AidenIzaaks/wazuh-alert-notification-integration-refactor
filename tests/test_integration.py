import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch
from wazuh_sql_alert.common import parse_wazuh_alert
from wazuh_sql_alert.runner import run

ROOT = Path(__file__).resolve().parents[1]
ALERT = ROOT / "tests/fixtures/sql_alert.json"


def test_imports():
    import wazuh_sql_alert.services.email
    import wazuh_sql_alert.services.teams
    import wazuh_sql_alert.services.telegram


def test_parser():
    data = parse_wazuh_alert(json.loads(ALERT.read_text()))
    assert data["database_name"] == "Metro_Nam"
    assert data["action"] == "UP"


def test_dry_run():
    config = json.loads((ROOT / "config.example.json").read_text())
    assert run(ALERT, config, dry_run=True) == "processed"


def test_subprocess_from_unrelated_cwd(tmp_path):
    config = ROOT / "config.example.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "wazuh_sql_alert.runner",
            str(ALERT),
            "",
            "",
            "--config",
            str(config),
            "--dry-run",
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
