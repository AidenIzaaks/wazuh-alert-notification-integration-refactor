from email.message import EmailMessage
import json
import smtplib
import ssl

from wazuh_sql_alert.common import action_map

# Initialized by the entry point before sending; no I/O at import time.
SENDER_EMAIL = ""
SMTP_SERVER = ""
SMTP_PORT = 587
SENDER_PASSWORD = ""


def configure(config):
    global SENDER_EMAIL, SMTP_SERVER, SMTP_PORT, SENDER_PASSWORD
    settings = config["alerts"]["email"]
    SENDER_EMAIL = settings["sender"]
    SMTP_SERVER = settings["server"]
    SMTP_PORT = settings["port"]
    SENDER_PASSWORD = settings["password"]


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
