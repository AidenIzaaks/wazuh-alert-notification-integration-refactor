"""Wazuh custom integration adapter. One alert file per invocation."""
import json
import logging
import sys
from pathlib import Path
from wazuh_sql_alert.services import email, teams, telegram

logger = logging.getLogger(__name__)


def run(alert_path, config, *, dry_run=False):
    alert_json = Path(alert_path).read_text(encoding="utf-8")
    alert = json.loads(alert_json)
    appname = alert["data"]["app"]
    user = alert["data"]["dstuser"]
    ignore = config.get("ignore", {})
    if any(app in appname for app in ignore.get("apps", ["Arch Retail System", "SQLAgent"])):
        return "ignored_app"
    if any(user.startswith(prefix) for prefix in ignore.get("users", ["NT SERVICE", "NT AUTHORITY"])):
        return "ignored_user"

    alerts = config.get("alerts", {})
    email_settings = alerts.get("email", {})
    teams_settings = alerts.get("teams", {})
    telegram_settings = alerts.get("telegram", {})
    level = int(alert["rule"]["level"])
    if email_settings.get("sender") and email_settings.get("recipients") and email_settings.get("server") and level >= email_settings.get("min_level", 0):
        email.configure(config)
        subject, body = email.generate_msg(alert_json)
        if not dry_run:
            email.send_email(email_settings["recipients"], subject, body)
    if teams_settings.get("webhook_url") and config.get("wazuh_server_url"):
        teams.configure(config)
        if not dry_run:
            teams.generate_teams_card(alert_json)
    if telegram_settings.get("bot_token") and telegram_settings.get("chat_id"):
        telegram.TELEGRAM_MIN_ALERT_LEVEL = telegram_settings.get("min_level", 7)
        if not dry_run:
            telegram.send_telegram_sql_audit_alert(telegram_settings["bot_token"], telegram_settings["chat_id"], alert_json)
    return "processed"


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("alert_path")
    parser.add_argument("api_key", nargs="?", default="")
    parser.add_argument("hook_url", nargs="?", default="")
    parser.add_argument("--config", default="/var/ossec/etc/custom-integrations/sql-alert.json")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    result = run(args.alert_path, config, dry_run=args.dry_run)
    logger.info("Integration result: %s", result)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
