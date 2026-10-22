import json


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


def load_config(path="config.json"):
    with open(path, "r") as f:
        config = json.loads(f.read())
    return config


action_map = {
    "DR": "DROP",
    "DL": "DELETE",
    "CR": "CREATE",
    "AL": "ALTER",
    "IN": "INSERT",
    "UP": "UPDATE",
}

WAZUH_SERVER_URL = "https://192.168.0.17:8443/"
