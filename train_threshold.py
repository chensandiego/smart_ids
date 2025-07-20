import numpy as np
import csv
import os

# Configuration
MSE_LOG_FILE = "mse_values.csv"
ANOMALY_THRESHOLD_FILE = "model/anomaly_threshold.txt"
PERCENTILE = 99  # Use the 99th percentile of MSE values as the threshold

def train_threshold():
    print(f"Starting threshold training using {MSE_LOG_FILE}...")
    if not os.path.exists(MSE_LOG_FILE):
        print(f"Error: {MSE_LOG_FILE} not found. Please run detector.py in LEARNING_MODE first.")
        return

    mse_values = []
    with open(MSE_LOG_FILE, "r") as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for row in reader:
            try:
                mse_values.append(float(row[0]))
            except (ValueError, IndexError) as e:
                print(f"Skipping invalid row: {row} - {e}")
                continue

    if not mse_values:
        print("No MSE values found in the log file. Cannot train threshold.")
        return

    threshold = np.percentile(mse_values, PERCENTILE)

    # Ensure the model directory exists
    os.makedirs(os.path.dirname(ANOMALY_THRESHOLD_FILE), exist_ok=True)

    with open(ANOMALY_THRESHOLD_FILE, "w") as f:
        f.write(str(threshold))

    print(f"Threshold training complete. {PERCENTILE}th percentile MSE: {threshold:.4f}")
    print(f"Threshold saved to: {ANOMALY_THRESHOLD_FILE}")

if __name__ == "__main__":
    train_threshold()
