from scapy.all import IP, wrpcap
from sklearn.ensemble import IsolationForest
from joblib import load
import time
import json
import re
from database import insert_alert
from notifications import send_line_notification, send_slack_notification, export_to_csv
from enrichment import get_whois_info

model = load("model/isolation_forest_model.joblib")

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
        return [len(pkt), ip_layer.ttl, ip_layer.proto, ip_layer.len]
    return [0, 0, 0, 0]

def match_suricata_signature(pkt):
    raw = bytes(pkt).decode(errors="ignore")
    for sig in suricata_signatures:
        if sig['pattern'] in raw:
            return sig['msg']
    return None

def raise_alert(pkt, reason):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    src = pkt[IP].src if IP in pkt else "unknown"
    dst = pkt[IP].dst if IP in pkt else "unknown"

    # Enrich alert with Whois information
    whois_info = get_whois_info(src)

    alert = {
        "time": timestamp,
        "src": src,
        "dst": dst,
        "reason": reason,
        "whois": whois_info
    }

    # Save packet to PCAP file
    pcap_filename = f"alerts/{timestamp.replace(':', '-')}-{src}.pcap"
    wrpcap(pcap_filename, pkt)

    insert_alert(src, dst, reason)
    send_line_notification(alert)
    send_slack_notification(alert)
    export_to_csv(alert)
    print("[ALERT]", json.dumps(alert, ensure_ascii=False))

def packet_handler(pkt):
    if IP not in pkt:
        return
    msg = match_suricata_signature(pkt)
    if msg:
        raise_alert(pkt, f"簽章比對：{msg}")
        return

    features = extract_features(pkt)
    prediction = model.predict([features])
    if prediction[0] == -1:
        raise_alert(pkt, "異常流量偵測")
