# smart_ids

the repo only consider run on a single machine which is not scale out.
However, I have created a new version which adopts distribution design. It is in zip file.

will process wireshark pcap file to determine any potential threat

To use this feature, run the following command:

1 python ids.py --mode monitor

This will start the monitoring process. Any new PCAP files that are added to the wireshark_pcapoutput directory will be processed,
and any threats will be detected. The processed files will then be moved to the processed_pcaps directory.

I recommend you to test this new feature by adding some PCAP files to the wireshark_pcapoutput directory.

   * Core Logic: ids.py is the main entry point. It can run in three
     modes: live (real-time monitoring), pcap (analyzing a file), and
     monitor (monitoring a directory for new pcap files).
   * Detection: detector.py contains the core detection logic. It uses a
     machine learning model (isolation_forest_model.joblib) and Suricata
     rules to analyze packets and raise alerts.
   * Alerts: When an alert is raised, the raise_alert function in
     detector.py is called. This function saves the alert to a database
     (alerts.db), sends notifications via Line and Slack, and exports the
     alert to a CSV file.
   * Dependencies: The project uses scapy, scikit-learn, joblib, flask,
     requests, and python-whois.
   * Configuration: config.py stores configuration settings, including
     database name, rule paths, and notification service tokens.
