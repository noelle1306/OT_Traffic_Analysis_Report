import pandas as pd
from scapy.all import PcapReader, TCP, IP
import os
import glob
import ipaddress

# === CONFIGURATION ===
NORMAL_DIR = r"data/raw_pcaps"
ATTACK_DIR = r"data/attack_pcaps

# OUTPUT FILES
OUTPUT_NORMAL = r"data/processed/normal_features.csv"
OUTPUT_ATTACK = r"data/processed/attack_features.csv"

# === PERFORMANCE SETTINGS ===
NORMAL_LIMIT = None       
ATTACK_LIMIT = 300000     # Stop after 300,000 Modbus packets per attack file

def ip_to_int(ip_str):
    try:
        return int(ipaddress.IPv4Address(ip_str))
    except:
        return 0

def extract_features(folder_path, label_type, packet_limit=None):
    print(f"\n--- Scanning {label_type} Data in: {folder_path} ---")
    if packet_limit:
        print(f"    (Performance Mode: Stopping after {packet_limit} packets per file)")
    
    files = [f for f in glob.glob(os.path.join(folder_path, "*")) if f.endswith((".pcap", ".pcapng"))]
    
    if not files:
        print("No files found!")
        return []

    all_rows = []

    for pcap in files:
        print(f"Streaming {os.path.basename(pcap)}...")
        packet_count = 0
        file_packets = 0
        
        try:
            with PcapReader(pcap) as pcap_reader:
                prev_time = 0
                
                for pkt in pcap_reader:
                    # === PERFORMANCE CHECK ===
                    if packet_limit and file_packets >= packet_limit:
                        print(f"    -> Limit reached ({packet_limit}). Moving to next file.")
                        break

                    packet_count += 1
                    
                    # Progress Indicator (Every 10k packets)
                    if packet_count % 10000 == 0:
                        print(f"   ... scanned {packet_count} packets")

                    try:
                        # 1. Quick Layer Check
                        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                            continue
                            
                        # 2. Quick Port Check
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                        if sport != 502 and dport != 502:
                            continue
                            
                        # 3. Extract Features
                        curr_time = float(pkt.time)
                        if prev_time == 0:
                            dt = 0.0
                        else:
                            dt = curr_time - prev_time
                        
                        try:
                            src_ip = pkt[IP].src
                            src_ip_int = ip_to_int(src_ip)
                            
                            # === NEW: EXTRACT MODBUS FUNCTION CODE ===
                            # The Modbus Function Code is the 8th byte of the TCP payload
                            payload = bytes(pkt[TCP].payload)
                            if len(payload) > 7:
                                function_code = payload[7]
                            else:
                                function_code = 0 # Not a valid Modbus packet payload
                            # ==========================================

                        except:
                            continue 
                        
                        all_rows.append({
                            "delta_time": dt,
                            "packet_length": len(pkt),
                            "src_ip_int": src_ip_int,
                            "src_ip_str": src_ip,
                            "function_code": function_code,  # <--- SAVING THE ATTACK INDICATOR
                            "label": label_type
                        })
                        
                        prev_time = curr_time
                        file_packets += 1

                    except Exception:
                        continue
                        
            print(f" -> Finished {os.path.basename(pcap)}: Extracted {file_packets} packets.")

        except Exception as e:
            print(f"\nFailed to read file {pcap}: {e}")

    return all_rows

if __name__ == "__main__":
    # 1. Process Normal Data 
    normal_data = extract_features(NORMAL_DIR, "Normal", packet_limit=NORMAL_LIMIT)
    if normal_data:
        pd.DataFrame(normal_data).to_csv(OUTPUT_NORMAL, index=False)
        print(f"Saved {len(normal_data)} normal packets to {OUTPUT_NORMAL}")

    # 2. Process Attack Data 
    attack_data = extract_features(ATTACK_DIR, "Attack", packet_limit=ATTACK_LIMIT)
    if attack_data:
        pd.DataFrame(attack_data).to_csv(OUTPUT_ATTACK, index=False)
        print(f"Saved {len(attack_data)} attack packets to {OUTPUT_ATTACK}")
