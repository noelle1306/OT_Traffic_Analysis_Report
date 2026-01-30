import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# === CONFIGURATION ===
NORMAL_FILE = r"data/processed/normal_features.csv"
ISO_FOREST_REPORT = r"data/processed/iso_forest_report.csv"

def main():
    # 1. Load Data
    try:
        normal_df = pd.read_csv(NORMAL_FILE)
        anomaly_df = pd.read_csv(ISO_FOREST_REPORT)
    except FileNotFoundError as e:
        print(f"Error: Could not find files - {e}. Run 03_extract_features.py & 05_test_iso_forest.py scripts first!")
        return
    
    # 2. Count normal traffic
    normal_count = len(normal_df)
    
    # 3. Count anomalies by threat type
    anomaly_counts = anomaly_df['threat_type'].value_counts().to_dict()
    
    # Combine into single dataset: Normal Traffic + Anomaly Breakdown
    combined_counts = {"Normal Traffic": normal_count}
    combined_counts.update(anomaly_counts)
    
    counts = pd.Series(combined_counts)
    
    # 4. Generate Pie Chart
    plt.figure(figsize=(12, 8))
    
    # Define colors for threats
    colors = {
        "Normal Traffic": "#90EE90",                 # Light Green
        "CRITICAL: UNAUTHORIZED STOP COMMAND": "#cc0000",  # Dark Red
        "FOREIGN IP ACCESS": "#ff0000",              # Bright Red
        "DoS ATTACK (High Volume)": "#1900ff",       # Blue
        "Unknown Anomaly (Statistical Deviation)": "#ffaa00" # Light Orange
    }
    # Map colors to the counts index
    pie_colors = [colors.get(x, "#d9d9d9") for x in counts.index]

    # Custom function to show both count and percentage
    def make_autopct(values):
        def my_autopct(pct):
            total = sum(values)
            val = int(round(pct*total/100.0))
            # Only show label if percentage is > 2%, otherwise show in legend
            if pct > 2:
                return f'{val}\n({pct:.1f}%)'
            else:
                return ''
        return my_autopct

    wedges, texts, autotexts = plt.pie(
        counts, 
        labels=None,  # Don't show labels on pie (will use legend instead)
        autopct=make_autopct(counts), 
        startangle=140, 
        colors=pie_colors,
        explode=[0.05] * len(counts), # Explode all slices slightly
        shadow=True
    )
    
    # Add legend with all items
    legend_labels = [f'{label}: {count:,} packets' for label, count in zip(counts.index, counts.values)]
    plt.legend(legend_labels, loc='center left', bbox_to_anchor=(1, 0, 0.5, 1), fontsize=10)
    
    total_packets = normal_count + len(anomaly_df)
    plt.title(f"Network Traffic Analysis: Normal vs Anomalies (Total: {total_packets})", fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.show()

    # Optional: Print the breakdown
    print("\n=== Traffic Report ===")
    print(counts)
    print(f"\n[NORMAL] Normal Traffic: {normal_count} packets ({100*normal_count/total_packets:.1f}%)")
    print(f"[ANOMALY] Anomalies Detected: {len(anomaly_df)} packets ({100*len(anomaly_df)/total_packets:.1f}%)")

if __name__ == "__main__":
    main()