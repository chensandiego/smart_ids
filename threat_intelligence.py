import requests

class ThreatIntelligence:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def get_ip_reputation(self, ip_address):
        headers = {"x-apikey": self.api_key}
        response = requests.get(f"{self.base_url}/ip_addresses/{ip_address}", headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return None
