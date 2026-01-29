import pandas as pd
import joblib

# === CONFIGURATION ===
TEST_FILE = r"C:\Users\23012197\Documents\ot-ml-modbus\data\processed\attack_features.csv"
MODEL_PATH = r"C:\Users\23012197\Documents\ot-ml-modbus\models\iso_forest.pkl"

# YOUR WHITELIST (Update this with your factory's IPs)
ALLOWED_IPS = ['192.168.206.1', '192.168.206.20', '192.168.206.40']

def classify_threat(row):
    """
    Applies strict logic rules to explain the anomaly.
    """
    dt = row['delta_time']
    ip_str = row['src_ip_str']
    # Safely get function_code (defaults to 0 if missing)
    fc = row.get('function_code', 0) 
    
    # === RULE 1: CRITICAL UNAUTHORIZED WRITE ===
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

    return "Unknown Anomaly (Statistical Deviation)" # prevent more false positives

def main():
    # 1. Load Resources
    try:
        df = pd.read_csv(TEST_FILE)
        model = joblib.load(MODEL_PATH)
    except FileNotFoundError:
        print("Error: Missing data or model. Did you run Script 03 and 04?")
        return

    # Features used for the Isolation Forest MODEL (Note: function_code is NOT here, that's for the RULES above)
    features = ['delta_time', 'packet_length', 'src_ip_int']
    
    # 2. AI Prediction
    print(f"Scanning {len(df)} packets using Isolation Forest...")
    df['anomaly'] = model.predict(df[features]) # -1 = Anomaly
    
    # 3. Filter Anomalies
    # We create a copy to avoid SettingWithCopy warnings
    anomalies = df[df['anomaly'] == -1].copy()
    
    if len(anomalies) == 0:
        print("✅ No anomalies detected.")
        return

    # 4. Apply Rules
    anomalies['threat_type'] = anomalies.apply(classify_threat, axis=1)

    # 5. Report
    print(f"\n{'='*60}")
    print(f"🚨  ISOLATION FOREST REPORT: {len(anomalies)} THREATS")
    print(f"{'='*60}\n")
    
    counts = anomalies['threat_type'].value_counts()
    for threat, count in counts.items():
        print(f"⚠️  {threat}: {count} packets")
        # Show a sample of this threat
        sample = anomalies[anomalies['threat_type'] == threat].iloc[0]
        print(f"    -> Sample IP: {sample['src_ip_str']} | FuncCode: {sample.get('function_code', 'N/A')}")
        print("-" * 60)

    # Save
    anomalies.to_csv(r"C:\Users\23012197\Documents\ot-ml-modbus\data\processed\iso_forest_report.csv", index=False)

if __name__ == "__main__":
    main()