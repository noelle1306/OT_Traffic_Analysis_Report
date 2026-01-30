import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# === PATHS ===
INPUT_FILE = r"data/processed/normal_features.csv"
MODEL_PATH = r"models/iso_forest.pkl"

def main():
    print("Loading Normal Training Data...")
    try:
        df = pd.read_csv(INPUT_FILE)
    except FileNotFoundError:
        print("Error: Normal features file not found. Run Script 03 first.")
        return
    
    # Features to train on
    features = ['delta_time', 'packet_length', 'src_ip_int']
    X_train = df[features]
    
    print(f"Training Isolation Forest on {len(X_train)} packets...")
    
    # Contamination = 0.01 (We assume training data is 99% clean)
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(X_train)
    
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    main()