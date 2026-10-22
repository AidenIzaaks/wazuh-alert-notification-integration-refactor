#!/opt/wazuh-integrations/venv/bin/python3
import os
from email.message import EmailMessage
import ssl
import requests
import urllib.request
import json
import sys
import smtplib
from email.mime.text import MIMEText
import logging

# from services.teams import generate_teams_card

# Wazuh and Teams Variables
WAZUH_SERVER_URL = "REDACTED"
TEAMS_WEBHOOK_URL = "REDACTED"
TEAMS_MIN_ALERT_LEVEL = 0

# Telegram Credentials
BOT_TOKEN = "REDACTED"
CHAT_ID = "REDACTED"
TELEGRAM_MIN_ALERT_LEVEL = 7

# Email Credentials
SENDER_EMAIL = "genmon@metro.com.na"
FROM_EMAIL = SENDER_EMAIL
SENDER_PASSWORD = "REDACTED"
SMTP_SERVER = "smtp.office365.com"
SMTP_PORT = 587
EMAIL_MIN_ALERT_LEVEL = 0
TO_EMAIL = "REDACTED"

# Set log file path
LOG_FILE = "/var/ossec/logs/integrations.log"
PRODUCTION_DIR = "/opt/wazuh-integrations/"
SETTINGS_FILE = "config.json"

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logging.info(f"{__file__} integration started")

action_map = {
    "DR": "DROP",
    "DL": "DELETE",
    "CR": "CREATE",
    "AL": "ALTER",
    "IN": "INSERT",
    "UP": "UPDATE",
}


def parse_wazuh_alert(wazuh_data: dict) -> dict[str, str]:
    """
    Parse Wazuh alert JSON schema into a flat dictionary for message formatting.

    Args:
        wazuh_data (dict): The Wazuh alert JSON data

    Returns:
        dict: Flattened alert data for easy access
    """
    rule = wazuh_data.get("rule", {})
    agent = wazuh_data.get("agent", {})
    data = wazuh_data.get("data", {})
    db = data.get("db", {})

    return {
        "rule_id": str(rule.get("id", "N/A")),
        "rule_desc": rule.get("description", "N/A"),
        "level": str(rule.get("level", "N/A")),
        "timestamp": wazuh_data.get("timestamp", "N/A"),
        "database_name": db.get("database_name", "N/A"),
        "dst_user": data.get("dstuser", "N/A"),
        "object_name": db.get("object_name", "N/A"),
        "schema_name": db.get("schema_name", "N/A"),
        "agent_name": agent.get("name", "N/A"),
        "agent_ip": agent.get("ip", "N/A"),
        "location": wazuh_data.get("location", "N/A"),
        "group": ", ".join(rule.get("groups", [])),
        "sql_statement": db.get("statement", "N/A"),
        "action": data.get("action", "N/A"),
        "status": data.get("status", "N/A"),
        "success": data.get("success", "N/A"),
        "mitre_tactics": ", ".join(rule.get("mitre", {}).get("tactic", [])),
        "mitre_techniques": ", ".join(rule.get("mitre", {}).get("technique", [])),
        "mitre_ids": ", ".join(rule.get("mitre", {}).get("id", [])),
        "full_log": wazuh_data.get("full_log", "N/A"),
    }


def send_telegram_sql_audit_alert(
    bot_token: str, chat_id: str, alert_json: str, parse_mode: str = "HTML"
) -> dict:
    """
    Send a formatted SQL audit alert to Telegram.

    Args:
        bot_token (str): Your Telegram Bot Token from @BotFather
        chat_id (str): The chat ID to send the message to
        alert_data (dict): Dictionary containing alert information
        parse_mode (str): "HTML" or "MarkdownV2" (default: "HTML")

    Returns:
        dict: Response from Telegram API
    """

    # Telegram API endpoint
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    # Parse Alert
    alert_data = parse_wazuh_alert(json.loads(alert_json))

    # Determine severity emoji based on level
    level = alert_data.get("level", "0")
    if int(level) < TELEGRAM_MIN_ALERT_LEVEL:
        return
    try:
        level_num = int(level)
        if level_num >= 12:
            severity_emoji = "🔴"  # Critical
        elif level_num >= 7:
            severity_emoji = "🟠"  # High
        elif level_num >= 4:
            severity_emoji = "🟡"  # Medium
        else:
            severity_emoji = "🟢"  # Low
    except ValueError, TypeError:
        severity_emoji = "⚠️"

    # Action emoji
    action = alert_data.get("action", "").upper()
    action_emoji = {
        "DR": "🗑️",  # DROP
        "IN": "➕",  # INSERT
        "UP": "✏️",  # UPDATE
        "DL": "❌",  # DELETE
        "SL": "🔍",  # SELECT
        "EX": "⚙️",  # EXECUTE
    }.get(action, "📝")

    if parse_mode == "HTML":
        # HTML formatted message
        message = f"""<b>🔒 SQL AUDIT ALERT</b>
{severity_emoji} <b>Rule {alert_data.get("rule_id", "N/A")}</b> | Level {alert_data.get("level", "N/A")}

<b>📋 Description:</b>
{alert_data.get("rule_desc", "N/A")}

<b>━━━━━━━━━━━━━━━━━━━━</b>

<b>🕐 Timestamp:</b> {alert_data.get("timestamp", "N/A")}
<b>💾 Database:</b> {alert_data.get("database_name", "N/A")}
<b>📂 Schema:</b> {alert_data.get("schema_name", "N/A")}
<b>📦 Object:</b> {alert_data.get("object_name", "N/A")}
<b>👤 User:</b> {alert_data.get("dst_user", "N/A")}
<b>{action_emoji} Action:</b> {alert_data.get("action", "N/A")}
<b>✅ Success:</b> {alert_data.get("success", "N/A")}
<b>📊 Status:</b> {alert_data.get("status", "N/A")}

<b>━━━━━━━━━━━━━━━━━━━━</b>

<b>🖥️ Agent:</b> {alert_data.get("agent_name", "N/A")} ({alert_data.get("agent_ip", "N/A")})
<b>📍 Location:</b> {alert_data.get("location", "N/A")}
<b>🏷️ Groups:</b> {alert_data.get("group", "N/A")}"""

        # Add MITRE ATT&CK info if available
        mitre_tactics = alert_data.get("mitre_tactics", "")
        if mitre_tactics and mitre_tactics != "N/A":
            message += f"""

<b>━━━━━━━━━━━━━━━━━━━━</b>

<b>🎯 MITRE ATT&amp;CK:</b>
<b>Tactics:</b> {mitre_tactics}
<b>Techniques:</b> {alert_data.get("mitre_techniques", "N/A")}
<b>IDs:</b> {alert_data.get("mitre_ids", "N/A")}"""

        # Add SQL statement
        message += f"""

<b>━━━━━━━━━━━━━━━━━━━━</b>

<b>📝 SQL Statement:</b>
<code>{alert_data.get("sql_statement", "N/A")}</code>"""

    else:  # MarkdownV2
        # Escape special characters for MarkdownV2
        def escape_md(text):
            if not text:
                return "N/A"
            text = str(text)
            special_chars = [
                "_",
                "*",
                "[",
                "]",
                "(",
                ")",
                "~",
                "`",
                ">",
                "#",
                "+",
                "-",
                "=",
                "|",
                "{",
                "}",
                ".",
                "!",
            ]
            for char in special_chars:
                text = text.replace(char, f"\\{char}")
            return text

        message = f"""*🔒 SQL AUDIT ALERT*
{severity_emoji} *Rule {escape_md(alert_data.get("rule_id", "N/A"))}* \\| Level {escape_md(alert_data.get("level", "N/A"))}

*📋 Description:*
{escape_md(alert_data.get("rule_desc", "N/A"))}

━━━━━━━━━━━━━━━━━━━━

*🕐 Timestamp:* {escape_md(alert_data.get("timestamp", "N/A"))}
*💾 Database:* {escape_md(alert_data.get("database_name", "N/A"))}
*📂 Schema:* {escape_md(alert_data.get("schema_name", "N/A"))}
*📦 Object:* {escape_md(alert_data.get("object_name", "N/A"))}
*👤 User:* {escape_md(alert_data.get("dst_user", "N/A"))}
*{action_emoji} Action:* {escape_md(alert_data.get("action", "N/A"))}
*✅ Success:* {escape_md(alert_data.get("success", "N/A"))}
*📊 Status:* {escape_md(alert_data.get("status", "N/A"))}

━━━━━━━━━━━━━━━━━━━━

*🖥️ Agent:* {escape_md(alert_data.get("agent_name", "N/A"))} \\({escape_md(alert_data.get("agent_ip", "N/A"))}\\)
*📍 Location:* {escape_md(alert_data.get("location", "N/A"))}
*🏷️ Groups:* {escape_md(alert_data.get("group", "N/A"))}

━━━━━━━━━━━━━━━━━━━━

*📝 SQL Statement:*
```sql
{alert_data.get("sql_statement", "N/A")}
```"""

    # Prepare the payload
    payload = {"chat_id": chat_id, "text": message, "parse_mode": parse_mode}

    # Send the message
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {
            "error": str(e),
            "status_code": response.status_code if response else None,
        }


def generate_msg(alert_json):
    alert = json.loads(alert_json)

    # Extract relevant fields from the alert
    rule_id = alert["rule"]["id"]
    rule_desc = alert["rule"]["description"]
    agent_name = alert["agent"]["name"]
    timestamp = alert["timestamp"]
    full_log = alert["full_log"]
    level = alert["rule"]["level"]
    dstuser = alert["data"]["dstuser"]

    db = alert["data"]["db"]
    database_name = db["database_name"]
    object_name = db["object_name"]
    sql_statement = db["statement"]

    action = action_map[alert["data"]["action"]]

    # Check if the alert contains location and other optional fields
    location = alert["agent"]["ip"]
    group = (
        alert["rule"].get("groups", "N/A")[0] if alert["rule"].get("groups") else "N/A"
    )

    # Create the HTML message
    html_body = f"""
    <!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
  </head>
  <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f5f5f5; margin: 0; padding: 20px;">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 800px; margin: 0 auto; background-color: white; border: 1px solid #ddd; border-radius: 8px;">
      <!-- Header -->
      <tr>
        <td style="background-color: #f44336; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
          <h2 style="margin: 0; font-size: 24px;">🔒 SQL Audit Alert - Rule {rule_id}</h2>
        </td>
      </tr>

      <!-- Alert Details -->
      <tr>
        <td style="padding: 20px;">
          <p style="margin: 10px 0;"><strong>Rule Description:</strong> {rule_desc}</p>

          <!-- Info Grid -->
          <table width="100%" cellpadding="0" cellspacing="0" style="margin: 20px 0;">
            <tr>
              <td style="width: 50%; padding-right: 7px; padding-bottom: 15px;" valign="top">
                <div style="background-color: #f9f9f9; padding: 12px; border-left: 3px solid #f44336; border-radius: 4px;">
                  <strong style="display: block; color: #f44336; font-size: 12px; text-transform: uppercase; margin-bottom: 5px;">Severity Level</strong>
                  <span style="font-size: 14px; color: #333;">{level}</span>
                </div>
              </td>
              <td style="width: 50%; padding-left: 7px; padding-bottom: 15px;" valign="top">
                <div style="background-color: #f9f9f9; padding: 12px; border-left: 3px solid #f44336; border-radius: 4px;">
                  <strong style="display: block; color: #f44336; font-size: 12px; text-transform: uppercase; margin-bottom: 5px;">Timestamp</strong>
                  <span style="font-size: 14px; color: #333;">{timestamp}</span>
                </div>
              </td>
            </tr>
            <tr>
              <td style="width: 50%; padding-right: 7px; padding-bottom: 15px;" valign="top">
                <div style="background-color: #f9f9f9; padding: 12px; border-left: 3px solid #f44336; border-radius: 4px;">
                  <strong style="display: block; color: #f44336; font-size: 12px; text-transform: uppercase; margin-bottom: 5px;">Database Name</strong>
                  <span style="font-size: 14px; color: #333;">{database_name}</span>
                </div>
              </td>
              <td style="width: 50%; padding-left: 7px; padding-bottom: 15px;" valign="top">
                <div style="background-color: #f9f9f9; padding: 12px; border-left: 3px solid #f44336; border-radius: 4px;">
                  <strong style="display: block; color: #f44336; font-size: 12px; text-transform: uppercase; margin-bottom: 5px;">User</strong>
                  <span style="font-size: 14px; color: #333;">{dstuser}</span>
                </div>
              </td>
            </tr>
            <tr>
              <td style="width: 50%; padding-right: 7px; padding-bottom: 15px;" valign="top">
                <div style="background-color: #f9f9f9; padding: 12px; border-left: 3px solid #f44336; border-radius: 4px;">
                  <strong style="display: block; color: #f44336; font-size: 12px; text-transform: uppercase; margin-bottom: 5px;">Object Name</strong>
                  <span style="font-size: 14px; color: #333;">{object_name}</span>
                </div>
              </td>
              <td style="width: 50%; padding-left: 7px; padding-bottom: 15px;" valign="top">
                <div style="background-color: #f9f9f9; padding: 12px; border-left: 3px solid #f44336; border-radius: 4px;">
                  <strong style="display: block; color: #f44336; font-size: 12px; text-transform: uppercase; margin-bottom: 5px;">Agent</strong>
                  <span style="font-size: 14px; color: #333;">{agent_name}</span>
                </div>
              </td>
            </tr>
            <tr>
              <td style="width: 50%; padding-right: 7px;" valign="top">
                <div style="background-color: #f9f9f9; padding: 12px; border-left: 3px solid #f44336; border-radius: 4px;">
                  <strong style="display: block; color: #f44336; font-size: 12px; text-transform: uppercase; margin-bottom: 5px;">Location</strong>
                  <span style="font-size: 14px; color: #333;">{location}</span>
                </div>
              </td>
              <td style="width: 50%; padding-left: 7px;" valign="top">
                <div style="background-color: #f9f9f9; padding: 12px; border-left: 3px solid #f44336; border-radius: 4px;">
                  <strong style="display: block; color: #f44336; font-size: 12px; text-transform: uppercase; margin-bottom: 5px;">Rule Group</strong>
                  <span style="font-size: 14px; color: #333;">{group}</span>
                </div>
              </td>
            </tr>
          </table>

          <!-- SQL Statement Container -->
          <div style="margin: 20px 0; background-color: #282c34; border-radius: 6px; padding: 20px;">
            <div style="color: #61dafb; font-size: 14px; font-weight: bold; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 1px;">📝 SQL Statement</div>
            <div style="font-family: 'Courier New', Consolas, monospace; font-size: 14px; line-height: 1.5; color: #abb2bf; white-space: pre-wrap; word-wrap: break-word;">{sql_statement}</div>
          </div>

          <!-- Full Log Container -->
          <div style="margin: 20px 0; background-color: #f5f5f5; border: 1px solid #ddd; border-radius: 6px; padding: 15px;">
            <strong style="display: block; margin-bottom: 10px; color: #f44336;">Full Log:</strong>
            <pre style="margin: 0; font-family: 'Courier New', Consolas, monospace; font-size: 13px; white-space: pre-wrap; word-wrap: break-word;">{full_log}</pre>
          </div>
        </td>
      </tr>

      <!-- Footer -->
      <tr>
        <td style="padding: 20px; font-size: 12px; color: #666; text-align: center; background-color: #f9f9f9; border-top: 1px solid #ddd; border-radius: 0 0 8px 8px;">
          <p style="margin: 5px 0;">This is an automated notification from your Wazuh SQL Audit monitoring.</p>
          <p style="margin: 5px 0;">Please review and take appropriate action if necessary.</p>
        </td>
      </tr>
    </table>
  </body>
</html>
    """

    subject = f"Wazuh Alert - Level {level}: {rule_desc} on agent {agent_name}"

    return subject, html_body


def generate_teams_card(alert_json):
    alert = json.loads(alert_json)

    # Extract relevant fields from the alert
    rule_id = alert["rule"]["id"]
    rule_desc = alert["rule"]["description"]
    agent_name = alert["agent"]["name"]
    timestamp = alert["timestamp"]
    full_log = alert["full_log"]
    level = alert["rule"]["level"]
    dstuser = alert["data"]["dstuser"]

    db = alert["data"]["db"]
    database_name = db["database_name"]
    object_name = db["object_name"]
    sql_statement = db["statement"]

    if int(level) < TEAMS_MIN_ALERT_LEVEL:
        return

    action = action_map[alert["data"]["action"]]

    # Check if the alert contains location and other optional fields
    location = alert["agent"]["ip"]
    group = (
        alert["rule"].get("groups", "N/A")[0] if alert["rule"].get("groups") else "N/A"
    )

    payload = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {
                "type": "Container",
                "style": "attention",
                "items": [
                    {
                        "type": "ColumnSet",
                        "columns": [
                            {
                                "type": "Column",
                                "width": "auto",
                                "items": [
                                    {
                                        "type": "Image",
                                        "url": "https://img.icons8.com/fluency/48/000000/lock.png",
                                        "size": "Small",
                                    }
                                ],
                            },
                            {
                                "type": "Column",
                                "width": "stretch",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": "SQL Audit Alert",
                                        "weight": "Bolder",
                                        "size": "Large",
                                        "color": "Attention",
                                    },
                                    {
                                        "type": "TextBlock",
                                        "text": f"Rule {rule_id}",
                                        "size": "Medium",
                                        "weight": "Bolder",
                                        "spacing": "None",
                                    },
                                ],
                            },
                        ],
                    }
                ],
            },
            {
                "type": "Container",
                "separator": True,
                "spacing": "Medium",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": f"{rule_desc}",
                        "wrap": True,
                        "size": "Medium",
                        "weight": "Bolder",
                    }
                ],
            },
            {
                "type": "Container",
                "spacing": "Medium",
                "items": [
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "🔴 Severity Level:", "value": f"{level}"},
                            {"title": "🕐 Timestamp:", "value": f"{timestamp}"},
                            {"title": "💾 Database Name:", "value": f"{database_name}"},
                            {"title": "👤 User:", "value": f"{dstuser}"},
                            {"title": "📦 Object Name:", "value": f"{object_name}"},
                            {"title": "🖥️ Agent:", "value": f"{agent_name}"},
                            {"title": "📍 Location:", "value": f"{location}"},
                            {"title": "🏷️ Rule Group:", "value": f"{group}"},
                        ],
                    }
                ],
            },
            {
                "type": "Container",
                "separator": True,
                "spacing": "Medium",
                "style": "emphasis",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": "📝 SQL Statement",
                        "weight": "Bolder",
                        "size": "Medium",
                        "color": "Accent",
                    },
                    {
                        "type": "TextBlock",
                        "text": f"```sql\n{sql_statement}\n```",
                        "wrap": True,
                        "fontType": "Monospace",
                        "spacing": "Small",
                    },
                ],
            },
            {
                "type": "Container",
                "separator": True,
                "spacing": "Medium",
                "isVisible": False,
                "id": "fullLogContainer",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": "📋 Full Log",
                        "weight": "Bolder",
                        "size": "Medium",
                    },
                    {
                        "type": "TextBlock",
                        "text": f"{full_log}",
                        "wrap": True,
                        "fontType": "Monospace",
                        "spacing": "Small",
                        "maxLines": 10,
                    },
                ],
            },
        ],
        "actions": [
            {
                "type": "Action.ToggleVisibility",
                "title": "Show/Hide Full Log",
                "targetElements": ["fullLogContainer"],
            },
            {
                "type": "Action.OpenUrl",
                "title": "View in Wazuh",
                "url": f"{WAZUH_SERVER_URL}app/wazuh#/manager/?tab=ruleset&redirectRule={rule_id}",
                "style": "positive",
            },
            {
                "type": "Action.OpenUrl",
                "title": "Investigate",
                "url": f"{WAZUH_SERVER_URL}app/wazuh#/overview",
                "style": "default",
            },
        ],
        "msteams": {"width": "Full"},
    }
    json_payload = json.dumps(payload)
    data_bytes = json_payload.encode("utf-8")

    headers = {"Content-Type": "application/json"}

    req = urllib.request.Request(
        TEAMS_WEBHOOK_URL, data=data_bytes, headers=headers, method="POST"
    )

    try:
        with urllib.request.urlopen(req) as response:
            response_data = response.read().decode("utf-8")
            status_code = response.status
            print(f"Status: {status_code}")
            print(f"Response: {response_data}")
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code}")
        print(f"Response: {e.read().decode('utf-8')}")
    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")


def send_email(receiver_email, subject, body):
    msg = EmailMessage()
    msg.set_content("")
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = receiver_email

    msg.add_alternative(body, subtype="html")

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        print("Email sent successfully!")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        alert_file = sys.argv[1]
        with open(alert_file, "r") as f:
            alert_json = f.read()

        alert = json.loads(alert_json)
        appname = alert["data"]["app"]
        user = alert["data"]["dstuser"]

        settings = {}

        logging.info("This is the settings before", settings)
        if os.path.exists(PRODUCTION_DIR + SETTINGS_FILE):
            with open(PRODUCTION_DIR + SETTINGS_FILE, "r") as f:
                logging.info(f.read())
                settings = json.loads(f.read())

        logging.info(settings)

        ignore = settings.get("ignore", {})

        app_ignore = ignore.get("apps", ["Arch Retail System", "SQLAgent"])

        user_ignore = ignore.get("users", ["NT SERVICE", "NT AUTHORITY"])

        logging.info("Checking if source app is correct...")
        for app in app_ignore:
            if app in appname:
                logging.info("Wrong app")
                exit(1)

        logging.info("Checking if user is correct...")
        for iuser in user_ignore:
            if user.startswith(iuser):
                logging.info("Wrong user")
                exit(1)

        if not FROM_EMAIL or not TO_EMAIL or not SMTP_SERVER:
            logging.error("Email configuration is missing. Skipping email sending.")
        else:
            if int(json.loads(alert_json)["rule"]["level"]) < EMAIL_MIN_ALERT_LEVEL:
                pass
            else:
                subject, body = generate_msg(alert_json)
                send_email(TO_EMAIL, subject, body)
                logging.info("Email sent successfully.")

        if not TEAMS_WEBHOOK_URL or not WAZUH_SERVER_URL:
            logging.error("Teams webhook URL is missing. Skipping Teams notification.")
        else:
            generate_teams_card(alert_json)
            logging.info("Teams notification sent successfully.")

        if not BOT_TOKEN or not CHAT_ID:
            logging.error(
                "Telegram bot token or chat ID is missing. Skipping Telegram notification."
            )
        else:
            send_telegram_sql_audit_alert(BOT_TOKEN, CHAT_ID, alert_json)
            logging.info("Telegram notification sent successfully.")
