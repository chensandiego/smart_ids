

import time
import os
from scapy.all import rdpcap
from detector import packet_handler

# Define configurable paths for PCAP directories
PCAP_DIR = os.environ.get("PCAP_DIR", "/Users/chen/Desktop/smart_ids/wireshark_pcapoutput")
PROCESSED_DIR = os.environ.get("PROCESSED_DIR", "/Users/chen/Desktop/smart_ids/processed_pcaps")

def process_pcap(file_path):
    """Processes a single PCAP file."""
    print(f"📦 Processing PCAP file: {file_path}")
    try:
        packets = rdpcap(file_path)
        for pkt in packets:
            packet_handler(pkt)
    except Exception as e:
        print(f"Error processing PCAP file {file_path}: {e}")

def move_to_processed(file_path):
    """Moves a file to the processed directory."""
    if not os.path.exists(PROCESSED_DIR):
        os.makedirs(PROCESSED_DIR)
    try:
        os.rename(file_path, os.path.join(PROCESSED_DIR, os.path.basename(file_path)))
    except OSError as e:
        print(f"Error moving file {file_path}: {e}")

def monitor_directory():
    """Monitors a directory for new PCAP files and processes them."""
    print(f"👀 Monitoring directory for new PCAP files: {PCAP_DIR}")
    while True:
        for filename in os.listdir(PCAP_DIR):
            if filename.endswith(".pcap"):
                file_path = os.path.join(PCAP_DIR, filename)
                process_pcap(file_path)
                move_to_processed(file_path)
        time.sleep(5)

