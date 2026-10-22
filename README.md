# Wazuh SQL alert integration — organized edition

This refactor preserves the original formatting/sending functions in `src/wazuh_sql_alert/services/` with only import, configuration-injection, and syntax fixes. The original integration is retained under `legacy/` as a **redacted reference**, not a deployable fallback.

## Develop

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```

## Test Wazuh-style CLI locally

```bash
.venv/bin/python -m wazuh_sql_alert.runner tests/fixtures/sql_alert.json '' '' --config config.example.json --dry-run
```

## Deploy (staging first)

Install the package into `/opt/wazuh-integrations/venv`, copy `deploy/custom-sql_server_alert` to `/var/ossec/integrations/custom-sql_server_alert`, and set suitable executable permissions. Create a restricted real configuration file at `/var/ossec/etc/custom-integrations/sql-alert.json` (the example contains placeholders). The shebang must match the real virtualenv interpreter path.

## Important compatibility notes

- Original script is not syntactically runnable as supplied because several credential assignments are masked; the refactor uses runtime configuration instead.
- `runner.py` reproduces app/user ignore filters, severity gating, and calls the existing service formatting/sending functions. Validate parity against sanitized real alerts before production.
- Email, Teams and Telegram implementations retain their original exception handling and network behavior. No live sending occurs in `--dry-run`.
- The subprocess test uses the same argument layout, but does not prove Wazuh's runtime UID/GID or manager dispatch behavior.
- Never commit real config files or tokens. Rotate any credentials that were previously committed.
