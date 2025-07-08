
import os
from scapy.all import PcapReader, IP
from sklearn.ensemble import IsolationForest
from joblib import dump

PCAP_DIR = "wireshark_pcapoutput"
MODEL_PATH = "model/isolation_forest_model.joblib"

def extract_features(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        return [len(pkt), ip_layer.ttl, ip_layer.proto, ip_layer.len]
    return None

def train_model():
    print("Starting model training...")
    features = []
    batch_size = 10000  # Process 10,000 packets at a time

    for filename in os.listdir(PCAP_DIR):
        if filename.endswith(".pcap"):
            file_path = os.path.join(PCAP_DIR, filename)
            print(f"Extracting features from: {file_path}")
            try:
                with PcapReader(file_path) as pcap_reader:
                    for pkt in pcap_reader:
                        feature = extract_features(pkt)
                        if feature:
                            features.append(feature)
                        if len(features) == batch_size:
                            print(f"Training on a batch of {batch_size} packets...")
                            model = IsolationForest()
                            model.fit(features)
                            features = [] # Reset for next batch
            except Exception as e:
                print(f"Error processing {file_path}: {e}")

    if features:
        print(f"Training on the final batch of {len(features)} packets...")
        model = IsolationForest()
        model.fit(features)

    if 'model' in locals():
        print(f"Saving model to: {MODEL_PATH}")
        dump(model, MODEL_PATH)
        print("Model training complete.")
    else:
        print("No model was trained. Check for errors or empty pcap files.")

if __name__ == "__main__":
    train_model()
