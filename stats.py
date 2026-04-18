from collections import defaultdict


class TrafficStats:
    """
    Tracks packet counts per protocol and displays statistics.
    """

    def __init__(self):
        self.protocol_count = defaultdict(int)
        self.total_packets = 0

    def show_statistics(self, logger):
        logger.info("\n===== TRAFFIC ANALYSIS =====")
        for proto, count in self.protocol_count.items():
            percentage = (count / self.total_packets) * 100
            logger.info(f"{proto}: {count} packets ({percentage:.2f}%)")
        logger.info(f"Total Packets: {self.total_packets}\n")
