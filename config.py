
import os

# Database settings
DB_NAME = "alerts.db"

# Rule settings
SURICATA_RULES = "rules/suricata.rules"

# Notification settings
LINE_TOKEN = os.environ.get("LINE_TOKEN")
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK")

# Web dashboard settings
WEB_HOST = "127.0.0.1"
WEB_PORT = 5000
