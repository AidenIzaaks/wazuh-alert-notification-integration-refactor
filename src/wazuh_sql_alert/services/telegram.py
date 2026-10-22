import json
import requests
from wazuh_sql_alert.common import parse_wazuh_alert

TELEGRAM_MIN_ALERT_LEVEL = 7


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
    except (ValueError, TypeError):
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
