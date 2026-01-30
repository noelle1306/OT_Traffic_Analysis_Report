# OT Modbus Network Anomaly Detection

This repository contains a pipeline for detecting anomalies in OT Modbus TCP traffic using Isolation Forest and One-Class SVM, plus a Streamlit dashboard for visualizing results.

## Notes

- Please unzip attack features.zip to have the uncompressed version of `attack_features.csv` due to the size being too large when adding to GitHub
- As the website is using Streamlit, do click on this website to see it

## Features

- Read and preview raw PCAP and PCAPNG network captures.
- Extract Modbus-specific features (time gaps, packet length, source IP, function code) from normal and attack traffic
- Train unsupervised anomaly detection models:
  - Isolation Forest.
  - One-Class SVM with scaling.
- Score attack traffic, classify threats found from CSV reports.
- Generate CSV reports and visual plots.
- Streamlit web UI for interactive dashboard and cyber assistant.
- Able to download Anomaly Breakdown and Detected Anomalies into a CSV file


## Project Structure

- `01_read_pcap.py`  
  Preview all PCAP/PCAPNG files in the configured directory and print basic packet summaries.

- `02_filter_modbus.py`  
  Scan PCAP files and count Modbus TCP packets (port 502) per file and in total.

- `03_extract_features.py`  
  Stream PCAP files to extract features:
  - `delta_time` between packets
  - `packet_length`
  - `src_ip_int` and `src_ip_str`
  - Modbus `function_code` from TCP payload  
  Outputs:
  - `normal_features.csv`
  - `attack_features.csv`.

- `04_train_isolation_forest.py`  
  Train an Isolation Forest model on normal feature data and save `iso_forest.pkl`.

- `04b_train_ocsvm.py`  
  Train a One-Class SVM on scaled normal features and save both model and scaler (`ocsvm_model.pkl`, `ocsvm_model_scaler.pkl`).

- `05_test_iso_forest.py`  
  Apply Isolation Forest to attack features, filter anomalies, classify threat types using rules, and save `iso_forest_report.csv`.

- `05b_test_ocsvm.py`  
  Apply OCSVM (with scaler) to attack features, classify anomalies with the same rule set, and save `ocsvm_report.csv`.

- `06_plot_results.py`  
  Load normal data and Isolation Forest report, then generate a pie chart and textual breakdown of normal vs anomaly traffic by threat type.

- `streamlit_app.py`  
  Streamlit dashboard that:
  - Loads `normal_features.csv` and `iso_forest_report.csv`
  - Shows interactive pie and bar charts
  - Displays metrics, anomaly tables, and threat-type cards
  - Includes a “Cyber Assistant” page placeholder.

## Data and Paths

All scripts currently use absolute Windows paths under a root such as:

- `data/raw_pcaps` – normal PCAP files.
- `data/attack_pcaps` – attack PCAP files.
- `data/processed` – CSV outputs (`normal_features.csv`, `attack_features.csv`, `iso_forest_report.csv`, `ocsvm_report.csv`)
- `models` – trained model and scaler files (`iso_forest.pkl`, `ocsvm_model.pkl`, `ocsvm_model_scaler.pkl`).

Update these paths in each script to match your environment before running.

## Configuration

Key items to adjust:

- Directory paths (NORMAL_DIR, ATTACK_DIR, output and model paths).
- Whitelist of allowed IPs (ALLOWED_IPS list) in `05_test_iso_forest.py` and `05b_test_ocsvm.py`.
- Packet limits for performance (e.g., ATTACK_LIMIT in `03_extract_features.py`).
- Model hyperparameters in the training scripts (e.g., contamination for Isolation Forest, nu and kernel for OCSVM).

## Threat Classification Logic

Both testing scripts use rule-based logic on top of the anomaly scores:

- CRITICAL: UNAUTHORIZED STOP COMMAND – Modbus function codes in [5, 6, 15, 16] (unauthorized writes / stop actions).
- FOREIGN IP ACCESS – Source IP not in ALLOWED_IPS whitelist.
- DoS ATTACK (High Volume) – Consecutive packets with delta_time < 0.005 seconds.
- Unknown Anomaly (Statistical Deviation) – Anything else flagged by the model

## Install Dependencies

Create and activate a virtual environment, then install dependencies:

```bash
pip install -r requirements.txt
```
## Usage

Run the pipeline in this order:

Place normal PCAP files in `data/raw_pcaps` and attack PCAP files in `data/attack_pcaps`.

- Preview and sanity check PCAPs (optional):

```bash
python 01_read_pcap.py
```
```bash
python 02_filter_modbus.py
```

- Extract features:

```bash
python 03_extract_features.py
```
This generates `normal_features.csv` and `attack_features.csv` in `data/processed`.

- Train models:

```bash
python 04_train_isolation_forest.py
```
```bash
python 04b_train_ocsvm.py
```
Models and scaler are saved in the models directory.

- Test on attack data and generate reports:

```bash
python 05_test_iso_forest.py
```
```bash
python 05b_test_ocsvm.py
```
This creates `iso_forest_report.csv `and `ocsvm_report.csv` in `data/processed`.

- Plot results (static matplotlib view):

```bash
python 06_plot_results.py
```
This displays a pie chart and prints a textual breakdown.

- Launch Streamlit dashboard:

```bash
streamlit run streamlit_app.py
```

The app reads `normal_features.csv` and `iso_forest_report.csv` from `data/processed` to render interactive visualizations and alerts.

