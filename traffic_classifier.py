from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
 
# Dictionary to store protocol counts
protocol_count = defaultdict(int)
 
total_packets = 0
 
def classify_packet(packet):
    global total_packets
    total_packets += 1
 
    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = "OTHER"
 
    protocol_count[protocol] += 1
 
    print(f"Packet #{total_packets}: {protocol}")
 
def show_statistics():
    print("\n===== TRAFFIC ANALYSIS =====")
 
    for protocol, count in protocol_count.items():
        percentage = (count / total_packets) * 100
        print(f"{protocol}: {count} packets ({percentage:.2f}%)")
 
    print(f"\nTotal Packets Captured: {total_packets}")
 
try:
    packet_count = int(input("Enter the number of packets to capture: "))
    if packet_count <= 0:
        raise ValueError("Must be a positive integer.")
except ValueError as e:
    print(f"Invalid input: {e}")
    exit(1)
 
print(f"\nStarting Traffic Classification... (Capturing {packet_count} packets)\n")
 
# Capture user-defined number of packets
sniff(prn=classify_packet, count=packet_count)
 
# Show final analysis
show_statistics()