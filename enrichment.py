
import whois
import requests
import socket
from datetime import datetime, timedelta

_MALICIOUS_IPS = set()
_LAST_UPDATE_TIME = None
FEODO_BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
SANS_DSHIELD_BLOCKLIST_URL = "https://isc.sans.edu/api/traffic/blocklist.txt"
UPDATE_INTERVAL_HOURS = 24

def get_hostname(ip_address):
    """Performs a reverse DNS lookup for a given IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "Unknown"

def _fetch_blocklist(url, name):
    print(f"Attempting to load {name} IP blocklist from {url}...")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        ips = set()
        for line in response.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.add(line)
        print(f"Successfully loaded {len(ips)} malicious IPs from {name}.")
        return ips
    except requests.exceptions.RequestException as e:
        print(f"Error loading {name} IP blocklist: {e}")
        return set()
    except Exception as e:
        print(f"An unexpected error occurred while loading {name} IP blocklist: {e}")
        return set()

def load_malicious_ips():
    global _MALICIOUS_IPS, _LAST_UPDATE_TIME
    
    all_malicious_ips = set()
    
    # Load Feodo IP blocklist
    feodo_ips = _fetch_blocklist(FEODO_BLOCKLIST_URL, "Feodo Tracker")
    all_malicious_ips.update(feodo_ips)
    
    # Load SANS DShield blocklist
    sans_ips = _fetch_blocklist(SANS_DSHIELD_BLOCKLIST_URL, "SANS DShield")
    all_malicious_ips.update(sans_ips)
    
    _MALICIOUS_IPS = all_malicious_ips
    _LAST_UPDATE_TIME = datetime.now()
    print(f"Total malicious IPs loaded: {len(_MALICIOUS_IPS)}")

def is_ip_malicious(ip_address):
    global _LAST_UPDATE_TIME
    # Load blocklist if it's the first time or if it's outdated
    if _LAST_UPDATE_TIME is None or (datetime.now() - _LAST_UPDATE_TIME) > timedelta(hours=UPDATE_INTERVAL_HOURS):
        load_malicious_ips()
    
    return ip_address in _MALICIOUS_IPS

def get_whois_info(ip_address):
    try:
        w = whois.whois(ip_address)
        return w
    except Exception as e:
        print(f"Whois lookup error: {e}")
        return None

# Initial load of the blocklist when the module is imported
load_malicious_ips()

