from scapy.all import IP, TCP, Raw, DNS, DNSQR, wrpcap
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
from collections import defaultdict
from datetime import datetime, timedelta
from config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_TIME_WINDOW, DNS_TUNNELING_THRESHOLD_QUERY_LENGTH, DNS_TUNNELING_RATE_LIMIT

# Dictionary to store failed login attempts: {ip: {'count': 0, 'last_attempt': datetime.min}}
failed_attempts = defaultdict(lambda: {'count': 0, 'last_attempt': datetime.min})

# Dictionary to store DNS query counts for rate limiting: {ip: [(timestamp, count)]}
dns_query_counts = defaultdict(lambda: {'count': 0, 'last_query_time': datetime.min})

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

def check_brute_force(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode(errors='ignore')
        
        # Check for generic login attempt patterns
        is_login_attempt = "password" in payload.lower() or "login failed" in payload.lower()

        # Check for SSH specific login failures (port 22 and common SSH failure messages)
        is_ssh_login_failure = False
        if pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
            if "authentication failed" in payload.lower() or "permission denied" in payload.lower():
                is_ssh_login_failure = True

        if is_login_attempt or is_ssh_login_failure:
            src_ip = pkt[IP].src
            current_time = datetime.now()

            # Reset count if last attempt was outside the time window
            if (current_time - failed_attempts[src_ip]['last_attempt']).total_seconds() > BRUTE_FORCE_TIME_WINDOW:
                failed_attempts[src_ip]['count'] = 0

            failed_attempts[src_ip]['count'] += 1
            failed_attempts[src_ip]['last_attempt'] = current_time

            if failed_attempts[src_ip]['count'] >= BRUTE_FORCE_THRESHOLD:
                raise_alert(pkt, f"Brute Force Attack detected from {src_ip} (failed attempts: {failed_attempts[src_ip]['count']})", attack_type="Brute Force")
                # Optionally, reset count after alert to prevent repeated alerts for the same ongoing attack
                failed_attempts[src_ip]['count'] = 0

def check_dns_tunneling(pkt):
    if pkt.haslayer(DNS) and pkt.qd:  # Check if it's a DNS packet and has a question section
        for qd in pkt.qd:
            qname = qd.qname.decode(errors='ignore').rstrip('.')
            src_ip = pkt[IP].src

            # Rule 1: Unusually long DNS query names
            if len(qname) > DNS_TUNNELING_THRESHOLD_QUERY_LENGTH:
                raise_alert(pkt, f"DNS Tunneling suspected: unusually long query name ({len(qname)} chars) from {src_ip} for {qname}", attack_type="DNS Tunneling")

            # Rule 2: High rate of DNS queries from a single source
            current_time = datetime.now()
            if (current_time - dns_query_counts[src_ip]['last_query_time']).total_seconds() > 1: # Reset count if more than 1 second passed
                dns_query_counts[src_ip]['count'] = 0
            
            dns_query_counts[src_ip]['count'] += 1
            dns_query_counts[src_ip]['last_query_time'] = current_time

            if dns_query_counts[src_ip]['count'] > DNS_TUNNELING_RATE_LIMIT:
                raise_alert(pkt, f"DNS Tunneling suspected: high query rate ({dns_query_counts[src_ip]['count']} queries/sec) from {src_ip}", attack_type="DNS Tunneling")

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

    # Check for brute force attempts
    check_brute_force(pkt)

    # Check for DNS tunneling attempts
    check_dns_tunneling(pkt)

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
