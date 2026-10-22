import json
import urllib.request
import urllib.error

from wazuh_sql_alert.common import action_map

TEAMS_WEBHOOK_URL = ""
TEAMS_MIN_ALERT_LEVEL = 0
WAZUH_SERVER_URL = ""


def configure(config):
    global TEAMS_WEBHOOK_URL, TEAMS_MIN_ALERT_LEVEL, WAZUH_SERVER_URL
    settings = config.get("alerts", {}).get("teams", {})
    TEAMS_WEBHOOK_URL = settings.get("webhook_url", "")
    TEAMS_MIN_ALERT_LEVEL = settings.get("min_level", 0)
    WAZUH_SERVER_URL = config.get("wazuh_server_url", "")


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
    print(payload)
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
