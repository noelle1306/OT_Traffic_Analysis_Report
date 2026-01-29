from scapy.all import rdpcap, TCP, IP
import os
import glob

# Directory path
pcap_dir = r"C:\Users\23012197\Documents\ot-ml-modbus\data\raw_pcaps"

# Find all files
files = [f for f in glob.glob(os.path.join(pcap_dir, "*")) if f.endswith(".pcap") or f.endswith(".pcapng")]

total_packets = 0
modbus_packets = 0

print(f"Scanning {len(files)} files in: {pcap_dir}\n")

for pcap_path in files:
    try:
        packets = rdpcap(pcap_path)
        file_modbus_count = 0
        
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                if pkt[TCP].sport == 502 or pkt[TCP].dport == 502:
                    file_modbus_count += 1
        
        print(f"File: {os.path.basename(pcap_path)}")
        print(f" - Total: {len(packets)}")
        print(f" - Modbus: {file_modbus_count}")
        
        total_packets += len(packets)
        modbus_packets += file_modbus_count
        
    except Exception as e:
        print(f"Error reading {pcap_path}: {e}")

print("-" * 30)
print(f"GRAND TOTAL Packets: {total_packets}")
print(f"GRAND TOTAL Modbus: {modbus_packets}")
