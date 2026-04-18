from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet

from classifier import classify_packet
from stats import TrafficStats


class TrafficClassifier(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrafficClassifier, self).__init__(*args, **kwargs)
        self.stats = TrafficStats()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)

        self.stats.total_packets += 1
        protocol = classify_packet(pkt)
        self.stats.protocol_count[protocol] += 1

        self.logger.info(f"Packet #{self.stats.total_packets}: {protocol}")

        if self.stats.total_packets % 10 == 0:
            self.stats.show_statistics(self.logger)
