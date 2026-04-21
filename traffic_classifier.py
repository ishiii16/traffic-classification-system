from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from collections import defaultdict


class TrafficClassifier(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrafficClassifier, self).__init__(*args, **kwargs)
        self.protocol_count = defaultdict(int)
        self.total_packets = 0

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        self.total_packets += 1
        protocol = "OTHER"
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            if pkt.get_protocol(tcp.tcp):
                protocol = "TCP"
            elif pkt.get_protocol(udp.udp):
                protocol = "UDP"
            elif pkt.get_protocol(icmp.icmp):
                protocol = "ICMP"
        self.protocol_count[protocol] += 1
        self.logger.info(f"Packet #{self.total_packets}: {protocol}")
        # Show stats every 10 packets
        if self.total_packets % 10 == 0:
            self.show_statistics()

    def show_statistics(self):
        self.logger.info("\n===== TRAFFIC ANALYSIS =====")
        for proto, count in self.protocol_count.items():
            percentage = (count / self.total_packets) * 100
            self.logger.info(f"{proto}: {count} packets ({percentage:.2f}%)")
        self.logger.info(f"Total Packets: {self.total_packets}\n")
