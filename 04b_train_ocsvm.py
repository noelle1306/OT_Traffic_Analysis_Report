import pandas as pd
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import joblib

# === PATHS ===
INPUT_FILE = r"C:\Users\23012197\Documents\ot-ml-modbus\data\processed\normal_features.csv"
MODEL_PATH = r"C:\Users\23012197\Documents\ot-ml-modbus\models\ocsvm_model.pkl"
SCALER_PATH = r"C:\Users\23012197\Documents\ot-ml-modbus\models\ocsvm_model_scaler.pkl"

def main():
    print("Loading Normal Training Data...")
    try:
        df = pd.read_csv(INPUT_FILE)
    except FileNotFoundError:
        print("Error: Normal features file not found. Run Script 03 first.")
        return
    
    features = ['delta_time', 'packet_length', 'src_ip_int']
    X_train = df[features]
    
    print(f"Scaling data and training OCSVM on {len(X_train)} packets...")
    
    # 1. Scale Data (Required for SVM)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # 2. Train Model
    # nu=0.01 (Similar to contamination, allows 1% outliers)
    model = OneClassSVM(nu=0.01, kernel="rbf", gamma='scale')
    model.fit(X_train_scaled)
    
    # 3. Save Both
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print("Model and Scaler saved successfully.")

if __name__ == "__main__":
    main()