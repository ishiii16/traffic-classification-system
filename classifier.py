from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp


def classify_packet(pkt):
    """
    Takes a Ryu packet object and returns the protocol as a string.
    Returns: "TCP", "UDP", "ICMP", or "OTHER"
    """
    ip_pkt = pkt.get_protocol(ipv4.ipv4)

    if ip_pkt:
        if pkt.get_protocol(tcp.tcp):
            return "TCP"
        elif pkt.get_protocol(udp.udp):
            return "UDP"
        elif pkt.get_protocol(icmp.icmp):
            return "ICMP"

    return "OTHER"
