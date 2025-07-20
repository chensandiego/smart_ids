
import whois
import requests
import socket
from datetime import datetime, timedelta

_MALICIOUS_IPS = set()
_LAST_UPDATE_TIME = None
FEODO_BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
UPDATE_INTERVAL_HOURS = 24

def get_hostname(ip_address):
    """Performs a reverse DNS lookup for a given IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "Unknown"

def load_feodo_ip_blocklist():
    global _MALICIOUS_IPS, _LAST_UPDATE_TIME
    print("Attempting to load Feodo IP blocklist...")
    try:
        response = requests.get(FEODO_BLOCKLIST_URL, timeout=10)
        response.raise_for_status()  # Raise an exception for HTTP errors
        
        new_malicious_ips = set()
        for line in response.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                new_malicious_ips.add(line)
        
        _MALICIOUS_IPS = new_malicious_ips
        _LAST_UPDATE_TIME = datetime.now()
        print(f"Successfully loaded {len(_MALICIOUS_IPS)} malicious IPs from Feodo Tracker.")
    except requests.exceptions.RequestException as e:
        print(f"Error loading Feodo IP blocklist: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while loading Feodo IP blocklist: {e}")

def is_ip_malicious(ip_address):
    global _LAST_UPDATE_TIME
    # Load blocklist if it's the first time or if it's outdated
    if _LAST_UPDATE_TIME is None or (datetime.now() - _LAST_UPDATE_TIME) > timedelta(hours=UPDATE_INTERVAL_HOURS):
        load_feodo_ip_blocklist()
    
    return ip_address in _MALICIOUS_IPS

def get_whois_info(ip_address):
    try:
        w = whois.whois(ip_address)
        return w
    except Exception as e:
        print(f"Whois lookup error: {e}")
        return None

# Initial load of the blocklist when the module is imported
load_feodo_ip_blocklist()

