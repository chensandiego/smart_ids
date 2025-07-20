import os
from scapy.all import PcapReader, IP
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.callbacks import EarlyStopping
import numpy as np
from joblib import dump

PCAP_DIR = "wireshark_pcapoutput"
MODEL_PATH = "model/autoencoder_model.h5"
SCALER_PATH = "model/scaler.joblib"

def extract_features(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        # Ensure all features are numerical and handle potential missing values gracefully
        return [float(len(pkt)), float(ip_layer.ttl), float(ip_layer.proto), float(ip_layer.len)]
    return None

def create_autoencoder(input_dim):
    input_layer = Input(shape=(input_dim,))
    encoder = Dense(64, activation="relu")(input_layer)
    encoder = Dense(32, activation="relu")(encoder)
    encoder = Dense(16, activation="relu")(encoder)

    decoder = Dense(32, activation="relu")(encoder)
    decoder = Dense(64, activation="relu")(decoder)
    decoder = Dense(input_dim, activation="sigmoid")(decoder) # Sigmoid for output between 0 and 1 (after scaling)

    autoencoder = Model(inputs=input_layer, outputs=decoder)
    autoencoder.compile(optimizer='adam', loss='mse')
    return autoencoder

def train_model():
    print("Starting model training...")
    all_features = []

    for filename in os.listdir(PCAP_DIR):
        if filename.endswith(".pcap"):
            file_path = os.path.join(PCAP_DIR, filename)
            print(f"Extracting features from: {file_path}")
            try:
                with PcapReader(file_path) as pcap_reader:
                    for pkt in pcap_reader:
                        feature = extract_features(pkt)
                        if feature:
                            all_features.append(feature)
            except Exception as e:
                print(f"Error processing {file_path}: {e}")

    if not all_features:
        print("No features extracted. Please ensure there are PCAP files in the wireshark_pcapoutput directory.")
        return

    all_features = np.array(all_features)

    # Scale features
    scaler = MinMaxScaler()
    scaled_features = scaler.fit_transform(all_features)
    dump(scaler, SCALER_PATH)
    print(f"Scaler saved to: {SCALER_PATH}")

    input_dim = scaled_features.shape[1]
    autoencoder = create_autoencoder(input_dim)

    print("Training Autoencoder...")
    # Use EarlyStopping to prevent overfitting
    early_stopping = EarlyStopping(monitor='loss', patience=5, restore_best_weights=True)
    autoencoder.fit(scaled_features, scaled_features, 
                      epochs=50, 
                      batch_size=32, 
                      shuffle=True, 
                      callbacks=[early_stopping],
                      verbose=1)

    print(f"Saving Autoencoder model to: {MODEL_PATH}")
    autoencoder.save(MODEL_PATH)
    print("Model training complete.")

if __name__ == "__main__":
    train_model()