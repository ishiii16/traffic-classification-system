from collections import defaultdict


class TrafficClassifier:
    """
    Protocol-level traffic classifier.

    Keeps running counters for each protocol label and exposes
    helper methods used by both the controller and the test suite.
    Intentionally contains NO Ryu imports so it can be unit-tested
    without a running OpenFlow environment.
    """

    KNOWN_PROTOCOLS = ("TCP", "UDP", "ICMP", "OTHER")

    def __init__(self):
        self.protocol_count: dict[str, int] = defaultdict(int)
        self.total_packets: int = 0

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def classify(self, has_ip: bool, has_tcp: bool, has_udp: bool, has_icmp: bool) -> str:
        """
        Return the protocol label for a single packet given boolean flags
        produced by the caller after inspecting the parsed packet headers.

        Priority: TCP > UDP > ICMP > OTHER (mirrors the original handler).
        Non-IP packets are always "OTHER".
        """
        if not has_ip:
            return "OTHER"
        if has_tcp:
            return "TCP"
        if has_udp:
            return "UDP"
        if has_icmp:
            return "ICMP"
        return "OTHER"

    # ------------------------------------------------------------------
    # Accounting
    # ------------------------------------------------------------------

    def record(self, protocol: str) -> None:
        """Increment counters for *protocol* and the global packet total."""
        self.total_packets += 1
        self.protocol_count[protocol] += 1

    def classify_and_record(
        self,
        has_ip: bool,
        has_tcp: bool = False,
        has_udp: bool = False,
        has_icmp: bool = False,
    ) -> str:
        """Convenience wrapper: classify, record, and return the label."""
        protocol = self.classify(has_ip, has_tcp, has_udp, has_icmp)
        self.record(protocol)
        return protocol

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_statistics(self) -> dict:
        """
        Return a dict with per-protocol counts and percentages plus the
        total packet count.  Safe to call even when total_packets == 0.
        """
        stats = {"total_packets": self.total_packets, "protocols": {}}
        for proto, count in self.protocol_count.items():
            pct = (count / self.total_packets * 100) if self.total_packets else 0.0
            stats["protocols"][proto] = {"count": count, "percentage": round(pct, 2)}
        return stats

    def format_statistics(self) -> str:
        """Return a human-readable statistics block (mirrors the original logger output)."""
        lines = ["\n===== TRAFFIC ANALYSIS ====="]
        for proto, count in self.protocol_count.items():
            pct = (count / self.total_packets * 100) if self.total_packets else 0.0
            lines.append(f"{proto}: {count} packets ({pct:.2f}%)")
        lines.append(f"Total Packets: {self.total_packets}\n")
        return "\n".join(lines)

    def reset(self) -> None:
        """Clear all counters (useful between test cases or operator resets)."""
        self.protocol_count = defaultdict(int)
        self.total_packets = 0
