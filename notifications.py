import requests
import csv
from config import LINE_TOKEN, SLACK_WEBHOOK

def send_line_notification(alert):
    if not LINE_TOKEN: return
    headers = {"Authorization": f"Bearer {LINE_TOKEN}"}
    message = f'【警示】\n時間: {alert["time"]}\n來源: {alert["src"]}\n目標: {alert["dst"]}\n原因: {alert["reason"]}'
    try:
        requests.post("https://notify-api.line.me/api/notify", headers=headers, data={"message": message})
    except requests.RequestException as e:
        print(f"LINE notification error: {e}")

def send_slack_notification(alert):
    if not SLACK_WEBHOOK: return
    message = {
        "text": f'*[入侵警示]* {alert["time"]}\n來源: {alert["src"]} → 目標: {alert["dst"]}\n原因: {alert["reason"]}'
    }
    try:
        requests.post(SLACK_WEBHOOK, json=message)
    except requests.RequestException as e:
        print(f"Slack notification error: {e}")

def export_to_csv(alert):
    try:
        with open("alerts.csv", "a", newline='') as f:
            writer = csv.writer(f)
            writer.writerow([alert["time"], alert["src"], alert["dst"], alert["reason"]])
    except IOError as e:
        print(f"CSV export error: {e}")
