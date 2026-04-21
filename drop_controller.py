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

from traffic_classifier import TrafficClassifier


class DropController(app_manager.RyuApp):
    """
    Ryu OpenFlow 1.3 application.

    Every packet-in event is classified by TrafficClassifier.
    A summary is printed to the Ryu logger every STATS_INTERVAL packets.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    STATS_INTERVAL = 10          # print stats after every N packets

    def __init__(self, *args, **kwargs):
        super(DropController, self).__init__(*args, **kwargs)
        self.classifier = TrafficClassifier()

    # ------------------------------------------------------------------
    # OpenFlow event handler
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)

        # Inspect headers and delegate classification + accounting
        ip_pkt   = pkt.get_protocol(ipv4.ipv4)
        has_ip   = ip_pkt is not None
        has_tcp  = pkt.get_protocol(tcp.tcp)  is not None
        has_udp  = pkt.get_protocol(udp.udp)  is not None
        has_icmp = pkt.get_protocol(icmp.icmp) is not None

        protocol = self.classifier.classify_and_record(has_ip, has_tcp, has_udp, has_icmp)

        self.logger.info(f"Packet #{self.classifier.total_packets}: {protocol}")

        if self.classifier.total_packets % self.STATS_INTERVAL == 0:
            self.logger.info(self.classifier.format_statistics())
