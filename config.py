
import os
import sys

# Database settings
DB_NAME = "alerts.db"

# Rule settings
SURICATA_RULES = "rules/suricata.rules"

# Notification settings
LINE_TOKEN = os.environ.get("LINE_TOKEN")
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK")

# Check for required environment variables
if not LINE_TOKEN:
    print("Warning: LINE_TOKEN environment variable not set. Line notifications will be disabled.")

if not SLACK_WEBHOOK:
    print("Warning: SLACK_WEBHOOK environment variable not set. Slack notifications will be disabled.")

# Web dashboard settings
WEB_HOST = "127.0.0.1"
WEB_PORT = 5000

# Behavioral Baseline settings
LEARNING_MODE = False  # Set to True to collect MSE values for threshold training
