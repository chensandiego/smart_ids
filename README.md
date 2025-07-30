# smart_ids

This repository contains an Intrusion Detection System (IDS) designed to process Wireshark PCAP files to identify potential threats. While the initial version focused on single-machine operation, this enhanced version incorporates more advanced detection capabilities.

## How to Use

### Configuration

Before running the application, you need to configure the following environment variables:

*   `LINE_TOKEN`: Your Line Notify token for receiving notifications.
*   `SLACK_WEBHOOK`: Your Slack webhook URL for receiving notifications.
*   `PCAP_DIR`: The directory to monitor for new PCAP files (defaults to `wireshark_pcapoutput`).
*   `PROCESSED_DIR`: The directory to move processed PCAP files to (defaults to `processed_pcaps`).
*   `VIRUSTOTAL_API_KEY`: Your VirusTotal API key for real-time threat intelligence.

### Installation

```bash
pip install -r requirements.txt
```

### Running the Application

To start the monitoring process, run the following command:

```bash
python ids.py --mode monitor
```

You can also enable automated model retraining:

```bash
python ids.py --mode monitor --retrain-interval 3600
```
This will monitor the `wireshark_pcapoutput` directory for new PCAP files. Any new files added will be processed, and threats will be detected. Processed files are then moved to the `processed_pcaps` directory.

**Recommendation:** Test this feature by adding some PCAP files to the `wireshark_pcapoutput` directory.

## Core Components and Enhancements

*   **Core Logic:** `ids.py` is the main entry point, supporting three modes: `live` (real-time monitoring), `pcap` (analyzing a single file), and `monitor` (monitoring a directory for new PCAP files).

*   **Detection:** `detector.py` contains the core detection logic. It now uses:
    *   **Enhanced ML Model (Autoencoder):** Replaced the Isolation Forest with a TensorFlow Keras Autoencoder for more sophisticated anomaly detection. This model learns patterns from "normal" network traffic.
    *   **Suricata Rules:** Continues to use Suricata rules for signature-based threat detection.
    *   **Brute Force Detection:** Implemented logic to detect brute force attacks by tracking failed login attempts within a configurable time window, including specific detection for SSH login failures.
    *   **ICMP Scan Detection:** Detects ICMP sweeps by tracking echo requests to multiple hosts from a single source within a specific time window.

*   **Alerts:** When an alert is raised, the `raise_alert` function in `detector.py` is called. This function:
    *   Saves the alert to a database (`alerts.db`).
    *   Sends notifications via Line and Slack.
    *   Exports the alert to a CSV file.
    *   **Threat Intelligence Enrichment:** Alerts are now enriched with information from multiple external threat intelligence feeds (e.g., Abuse.ch Feodo Tracker, SANS DShield). Source and destination IPs are checked against known malicious IP blacklists, and the alert includes flags (`is_src_malicious`, `is_dst_malicious`) if a match is found.
    *   **Real-Time Threat Intelligence:** Integrates with VirusTotal to provide real-time IP reputation checks.
    *   **DNS Lookup:** Performs a reverse DNS lookup to identify the hostname of the source IP address, providing more context for threat analysis.

*   **Web Dashboard:** The web dashboard has been enhanced with the following features:
    *   **Alert Filtering:** Filter alerts by source IP, destination IP, attack type, and time range.

*   **Indication of Attack (IoA):** A new `attack_type` column has been added to the `alerts` table in `alerts.db`. This column categorizes the type of attack detected (e.g., "Signature Match", "Anomaly Detection", "Brute Force", "DNS Tunneling") and is displayed on the dashboard for quick visualization of attack trends.

*   **Behavioral Baselines:** The system now supports dynamic anomaly thresholding based on learned normal behavior:
    *   **Learning Mode:** Set `LEARNING_MODE = True` in `config.py` and run `ids.py` with normal traffic. The system will log Mean Squared Error (MSE) values to `mse_values.csv`.
    *   **Threshold Training:** Run `python train_threshold.py` to calculate a dynamic anomaly threshold (e.g., 99th percentile of collected MSEs) and save it to `model/anomaly_threshold.txt`.
    *   **Detection Mode:** Set `LEARNING_MODE = False` in `config.py`. The system will load the calculated threshold for real-time anomaly detection.

*   **Automated Model Retraining:** The system can now automatically retrain the anomaly detection model and recalculate the anomaly threshold at specified intervals, ensuring the model stays up-to-date with evolving network patterns.

*   **Advanced Application Layer Protocol Analysis:** The system has been enhanced to detect common web-based attacks. While earlier versions focused on network and transport layers, this update adds detection for SQL injection and Cross-Site Scripting (XSS) by inspecting HTTP traffic for malicious payloads. Future work could involve expanding this to other application-layer protocols like FTP and SSH.

*   **Dependencies:** The project now uses `scapy`, `scikit-learn`, `joblib`, `flask`, `requests`, `python-whois`, and `tensorflow`.

*   **Configuration:** `config.py` stores configuration settings, including database name, rule paths, notification service tokens, `LEARNING_MODE` flag, and brute force detection thresholds.

## Model Training

To train the Autoencoder model, run:

```bash
python train_model.py
```

Ensure you have representative "normal" PCAP files in the `wireshark_pcapoutput` directory before training. The trained model (`autoencoder_model.h5`) and the feature scaler (`scaler.joblib`) will be saved in the `model/` directory. After model training, the anomaly threshold will also be automatically re-calculated.

## Generating Test Traffic

To test the IDS with various attack types, you can use the following scripts:

*   `generate_syn_flood.py`: Generates SYN flood traffic to simulate a Denial-of-Service (DoS) attack.
*   `generate_port_scan.py`: Generates port scan traffic to simulate a reconnaissance attack.
*   `generate_malware_traffic.py`: Generates traffic with a specific payload to simulate malware activity. (Requires a corresponding Suricata rule to trigger an alert, e.g., for "MALWARE_SIGNATURE_TEST").
*   `generate_web_attacks.py`: Generates traffic that simulates SQL injection and XSS attacks.

**Note:** Ensure your `ids.py` is running and monitoring traffic when generating test traffic. You may need to adjust the target IP addresses in the generation scripts to match your monitoring environment.
