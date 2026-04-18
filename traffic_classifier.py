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

print("Starting Traffic Classification...\n")

# Capture 50 packets
sniff(prn=classify_packet, count=50)

# Show final analysis
show_statistics()
