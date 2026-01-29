import pandas as pd
import joblib

# === CONFIGURATION ===
TEST_FILE = r"C:\Users\23012197\Documents\ot-ml-modbus\data\processed\attack_features.csv"
MODEL_PATH = r"C:\Users\23012197\Documents\ot-ml-modbus\models\ocsvm_model.pkl"
SCALER_PATH = r"C:\Users\23012197\Documents\ot-ml-modbus\models\ocsvm_model_scaler.pkl"

# YOUR WHITELIST (Update this with your factory's IPs)
ALLOWED_IPS = ['192.168.206.1', '192.168.206.20', '192.168.206.40']

def classify_threat(row):
    """
    Applies strict logic rules to explain the anomaly found by OCSVM.
    """
    dt = row['delta_time']
    ip_str = row['src_ip_str']
    
    # Safely get function_code (defaults to 0 if missing from CSV)
    fc = row.get('function_code', 0) 
    
    # === RULE 1: CRITICAL UNAUTHORIZED WRITE (The "Stop" Attack) ===
    # This detects the "On but not running" attack
    if fc in [5, 6, 15, 16]:
        return "CRITICAL: UNAUTHORIZED STOP COMMAND" # MACHINE STOPPAGE ATTACK

    # Rule 2: Foreign IP
    # This detects the foreign IP attack
    if ip_str not in ALLOWED_IPS:
        return "FOREIGN IP ACCESS"

    # Rule 3: DoS Attack (Too Fast < 0.005s)
    if dt < 0.005:
        return "DoS ATTACK (High Volume)"

    return "Unknown Anomaly (Statistical Deviation)"

def main():
    try:
        df = pd.read_csv(TEST_FILE)
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
    except FileNotFoundError:
        print("Error: Missing data, model, or scaler.")
        return

    # IMPORTANT: These must match exactly what you used in 04b_train_ocsvm.py
    # Do NOT add 'function_code' here, or the model will crash.
    features = ['delta_time', 'packet_length', 'src_ip_int']
    X = df[features]

    # 1. Scale Data (Mandatory for OCSVM)
    print("Scaling data and running OCSVM detection...")
    X_scaled = scaler.transform(X)

    # 2. Predict (-1 = Anomaly, 1 = Normal)
    df['anomaly'] = model.predict(X_scaled)

    # 3. Filter for Anomalies
    anomalies = df[df['anomaly'] == -1].copy()

    if len(anomalies) == 0:
        print("✅ No anomalies detected by OCSVM.")
        return

    # 4. Classify (This is where we use the Function Code)
    anomalies['threat_type'] = anomalies.apply(classify_threat, axis=1)

    # 5. Report
    print(f"\n{'='*60}")
    print(f"🚨  OCSVM REPORT: {len(anomalies)} THREATS")
    print(f"{'='*60}\n")
    
    counts = anomalies['threat_type'].value_counts()
    for threat, count in counts.items():
        print(f"⚠️  {threat}: {count} packets")
        # Show a sample of this threat
        sample = anomalies[anomalies['threat_type'] == threat].iloc[0]
        print(f"    -> Sample IP: {sample['src_ip_str']} | FuncCode: {sample.get('function_code', 'N/A')}")
        print("-" * 60)

    anomalies.to_csv(r"C:\Users\23012197\Documents\ot-ml-modbus\data\processed\ocsvm_report.csv", index=False)

if __name__ == "__main__":
    main()