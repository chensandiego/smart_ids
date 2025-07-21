from scapy.all import IP, wrpcap
from tensorflow.keras.models import load_model
from joblib import load
import numpy as np
import time
import json
import re
import datetime
from database import insert_alert
from notifications import send_line_notification, send_slack_notification, export_to_csv
from enrichment import get_whois_info, is_ip_malicious, get_hostname
from config import LEARNING_MODE
import csv

# Load the trained Autoencoder model and scaler
autoencoder_model = load_model("model/autoencoder_model.h5")
scaler = load("model/scaler.joblib")

# Define a threshold for anomaly detection (this will likely need tuning)
if not LEARNING_MODE:
    try:
        with open("model/anomaly_threshold.txt", "r") as f:
            ANOMALY_THRESHOLD = float(f.read().strip())
        print(f"Loaded ANOMALY_THRESHOLD: {ANOMALY_THRESHOLD}")
    except FileNotFoundError:
        print("WARNING: model/anomaly_threshold.txt not found. Using default ANOMALY_THRESHOLD = 0.01. Please run train_threshold.py after training the model.")
        ANOMALY_THRESHOLD = 0.01  # Default if file not found
else:
    print("Running in LEARNING_MODE. MSE values will be logged to mse_values.csv.")
    MSE_LOG_FILE = "mse_values.csv"
    # Clear the log file at the start of learning mode
    with open(MSE_LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["mse"])


def load_suricata_signatures(rule_path="rules/suricata.rules"):
    signatures = []
    with open(rule_path, 'r') as f:
        for line in f:
            if line.startswith('alert'):
                try:
                    msg = re.findall(r'msg:"([^"]+)"', line)[0]
                    pattern = re.findall(r'content:"([^"]+)"', line)[0]
                    signatures.append({'msg': msg, 'pattern': pattern})
                except:
                    continue
    return signatures

suricata_signatures = load_suricata_signatures()

def extract_features(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        return np.array([float(len(pkt)), float(ip_layer.ttl), float(ip_layer.proto), float(ip_layer.len)]).reshape(1, -1)
    return None

def match_suricata_signature(pkt):
    raw = bytes(pkt).decode(errors="ignore")
    for sig in suricata_signatures:
        if sig['pattern'] in raw:
            return sig['msg']
    return None

def raise_alert(pkt, reason, attack_type=None):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    src = pkt[IP].src if IP in pkt else "unknown"
    dst = pkt[IP].dst if IP in pkt else "unknown"

    # Enrich alert with Whois information and hostname
    whois_info = get_whois_info(src)
    hostname = get_hostname(src)
    is_src_malicious = is_ip_malicious(src)
    is_dst_malicious = is_ip_malicious(dst)

    alert = {
        "time": timestamp,
        "src": src,
        "dst": dst,
        "reason": reason,
        "hostname": hostname,
        "whois": whois_info,
        "is_src_malicious": is_src_malicious,
        "is_dst_malicious": is_dst_malicious
    }

    # Save packet to PCAP file
    pcap_filename = f"alerts/{timestamp.replace(':', '-')}-{src}.pcap"
    wrpcap(pcap_filename, pkt)

    insert_alert(src, dst, reason, hostname, attack_type)
    send_line_notification(alert)
    send_slack_notification(alert)
    export_to_csv(alert)

    # Convert datetime objects to strings for JSON serialization
    if whois_info:
        for key, value in whois_info.items():
            if isinstance(value, list):
                whois_info[key] = [str(v) for v in value]
            elif isinstance(value, datetime.datetime):
                whois_info[key] = value.isoformat()

    print("[ALERT]", json.dumps(alert, ensure_ascii=False))

def packet_handler(pkt):
    if IP not in pkt:
        return
    msg = match_suricata_signature(pkt)
    if msg:
        raise_alert(pkt, f"簽章比對：{msg}", attack_type="Signature Match")
        return

    features = extract_features(pkt)
    if features is None:
        return

    # Scale the features using the loaded scaler
    scaled_features = scaler.transform(features)

    # Get the reconstruction from the autoencoder
    reconstructed_features = autoencoder_model.predict(scaled_features)

    # Calculate the reconstruction error (Mean Squared Error)
    mse = np.mean(np.power(scaled_features - reconstructed_features, 2), axis=1)

    # Check if the reconstruction error exceeds the anomaly threshold
    if LEARNING_MODE:
        with open(MSE_LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([mse[0]])
    elif mse[0] > ANOMALY_THRESHOLD:
        raise_alert(pkt, f"異常流量偵測 (MSE: {mse[0]:.4f})", attack_type="Anomaly Detection")
