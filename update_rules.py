
import requests
import os

# URL for the Emerging Threats Open ruleset for Suricata
RULE_URL = "https://rules.emergingthreats.net/open/suricata/emerging-all.rules"

# Path to save the downloaded rules
RULE_PATH = os.path.join("rules", "suricata.rules")

def update_suricata_rules():
    """Downloads the latest Suricata rules from Emerging Threats."""
    print(f"Downloading Suricata rules from {RULE_URL}...")
    try:
        response = requests.get(RULE_URL)
        response.raise_for_status()  # Raise an exception for bad status codes

        with open(RULE_PATH, "w") as f:
            f.write(response.text)

        print(f"Successfully updated Suricata rules in {RULE_PATH}")

    except requests.exceptions.RequestException as e:
        print(f"Error downloading rules: {e}")

if __name__ == "__main__":
    update_suricata_rules()
