from scapy.all import rdpcap
import os
import glob

# === CONFIGURATION ===
# Pointing to the directory containing all your raw PCAP files
PCAP_DIR = r"C:\Users\23012197\Documents\ot-ml-modbus\data\raw_pcaps"

def preview_pcap(pcap_path):
    print(f"\nReading: {os.path.basename(pcap_path)}")
    try:
        packets = rdpcap(pcap_path)
        print(f"Total packets: {len(packets)}")
        
        # Print a summary of the first 5 packets in this file
        for i, pkt in enumerate(packets[:5]):
            print(f"  [Pkt {i+1}] {pkt.summary()}")
            
    except Exception as e:
        print(f"  Error reading file: {e}")

# === MAIN EXECUTION ===
if __name__ == "__main__":
    # Find all .pcap and .pcapng files in the directory
    search_path = os.path.join(PCAP_DIR, "*")
    files = [f for f in glob.glob(search_path) if f.endswith(".pcap") or f.endswith(".pcapng")]

    if not files:
        print(f"No PCAP files found in {PCAP_DIR}")
    else:
        print(f"Found {len(files)} PCAP files. Generating previews...")
        for pcap_file in files:
            preview_pcap(pcap_file)
