"""
regression_test.py
==================
Regression tests for TrafficClassifier (traffic_classifier.py).

Run with:
    python -m pytest regression_test.py -v
or:
    python regression_test.py
"""

import sys
import os
import unittest
from collections import defaultdict

# Allow running from the same directory as traffic_classifier.py
sys.path.insert(0, os.path.dirname(__file__))

from traffic_classifier import TrafficClassifier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _feed(clf: TrafficClassifier, packets: list[dict]) -> None:
    """Feed a list of packet-flag dicts into the classifier."""
    for p in packets:
        clf.classify_and_record(
            has_ip=p.get("ip", False),
            has_tcp=p.get("tcp", False),
            has_udp=p.get("udp", False),
            has_icmp=p.get("icmp", False),
        )


# ---------------------------------------------------------------------------
# Classification correctness
# ---------------------------------------------------------------------------

class TestClassifyMethod(unittest.TestCase):
    """Unit tests for TrafficClassifier.classify() in isolation."""

    def setUp(self):
        self.clf = TrafficClassifier()

    def test_tcp_packet(self):
        self.assertEqual(self.clf.classify(True, True, False, False), "TCP")

    def test_udp_packet(self):
        self.assertEqual(self.clf.classify(True, False, True, False), "UDP")

    def test_icmp_packet(self):
        self.assertEqual(self.clf.classify(True, False, False, True), "ICMP")

    def test_ip_only_no_transport(self):
        """IP packet with no recognised L4 → OTHER."""
        self.assertEqual(self.clf.classify(True, False, False, False), "OTHER")

    def test_non_ip_packet(self):
        """ARP / raw Ethernet (no IP) → OTHER regardless of L4 flags."""
        self.assertEqual(self.clf.classify(False, False, False, False), "OTHER")

    def test_non_ip_with_flags_still_other(self):
        """Non-IP with spurious L4 flags must still return OTHER."""
        self.assertEqual(self.clf.classify(False, True, True, True), "OTHER")

    def test_tcp_priority_over_udp(self):
        """If somehow both TCP and UDP flags are set, TCP wins."""
        self.assertEqual(self.clf.classify(True, True, True, False), "TCP")

    def test_tcp_priority_over_icmp(self):
        self.assertEqual(self.clf.classify(True, True, False, True), "TCP")

    def test_udp_priority_over_icmp(self):
        self.assertEqual(self.clf.classify(True, False, True, True), "UDP")


# ---------------------------------------------------------------------------
# Accounting / counters
# ---------------------------------------------------------------------------

class TestCounters(unittest.TestCase):

    def setUp(self):
        self.clf = TrafficClassifier()

    def test_total_packet_count(self):
        packets = [
            {"ip": True, "tcp": True},
            {"ip": True, "udp": True},
            {"ip": False},
        ]
        _feed(self.clf, packets)
        self.assertEqual(self.clf.total_packets, 3)

    def test_protocol_counts(self):
        packets = [
            {"ip": True, "tcp": True},
            {"ip": True, "tcp": True},
            {"ip": True, "udp": True},
            {"ip": True, "icmp": True},
            {"ip": False},
        ]
        _feed(self.clf, packets)
        self.assertEqual(self.clf.protocol_count["TCP"],   2)
        self.assertEqual(self.clf.protocol_count["UDP"],   1)
        self.assertEqual(self.clf.protocol_count["ICMP"],  1)
        self.assertEqual(self.clf.protocol_count["OTHER"], 1)

    def test_record_increments_independently(self):
        self.clf.record("TCP")
        self.clf.record("TCP")
        self.clf.record("UDP")
        self.assertEqual(self.clf.protocol_count["TCP"], 2)
        self.assertEqual(self.clf.protocol_count["UDP"], 1)
        self.assertEqual(self.clf.total_packets, 3)

    def test_classify_and_record_returns_label(self):
        label = self.clf.classify_and_record(True, True, False, False)
        self.assertEqual(label, "TCP")
        self.assertEqual(self.clf.total_packets, 1)

    def test_empty_classifier_zero_total(self):
        self.assertEqual(self.clf.total_packets, 0)
        self.assertEqual(len(self.clf.protocol_count), 0)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

class TestStatistics(unittest.TestCase):

    def setUp(self):
        self.clf = TrafficClassifier()

    def test_get_statistics_structure(self):
        _feed(self.clf, [{"ip": True, "tcp": True}, {"ip": True, "udp": True}])
        stats = self.clf.get_statistics()
        self.assertIn("total_packets", stats)
        self.assertIn("protocols", stats)
        self.assertEqual(stats["total_packets"], 2)

    def test_percentage_calculation(self):
        packets = [{"ip": True, "tcp": True}] * 3 + [{"ip": True, "udp": True}]
        _feed(self.clf, packets)
        stats = self.clf.get_statistics()
        self.assertAlmostEqual(stats["protocols"]["TCP"]["percentage"], 75.0)
        self.assertAlmostEqual(stats["protocols"]["UDP"]["percentage"], 25.0)

    def test_percentages_sum_to_100(self):
        packets = (
            [{"ip": True, "tcp":  True}] * 4 +
            [{"ip": True, "udp":  True}] * 3 +
            [{"ip": True, "icmp": True}] * 2 +
            [{"ip": False}]
        )
        _feed(self.clf, packets)
        stats = self.clf.get_statistics()
        total_pct = sum(v["percentage"] for v in stats["protocols"].values())
        self.assertAlmostEqual(total_pct, 100.0, places=1)

    def test_get_statistics_no_packets(self):
        """Should not raise ZeroDivisionError on empty classifier."""
        stats = self.clf.get_statistics()
        self.assertEqual(stats["total_packets"], 0)
        self.assertEqual(stats["protocols"], {})

    def test_format_statistics_contains_total(self):
        _feed(self.clf, [{"ip": True, "tcp": True}])
        output = self.clf.format_statistics()
        self.assertIn("Total Packets: 1", output)
        self.assertIn("TCP", output)

    def test_format_statistics_header(self):
        output = self.clf.format_statistics()
        self.assertIn("TRAFFIC ANALYSIS", output)


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------

class TestReset(unittest.TestCase):

    def test_reset_clears_counters(self):
        clf = TrafficClassifier()
        _feed(clf, [{"ip": True, "tcp": True}] * 5)
        clf.reset()
        self.assertEqual(clf.total_packets, 0)
        self.assertEqual(len(clf.protocol_count), 0)

    def test_reset_then_recount(self):
        clf = TrafficClassifier()
        _feed(clf, [{"ip": True, "udp": True}] * 3)
        clf.reset()
        _feed(clf, [{"ip": True, "tcp": True}])
        self.assertEqual(clf.total_packets, 1)
        self.assertEqual(clf.protocol_count["TCP"], 1)
        self.assertNotIn("UDP", clf.protocol_count)


# ---------------------------------------------------------------------------
# Regression scenarios (end-to-end flows)
# ---------------------------------------------------------------------------

class TestRegressionScenarios(unittest.TestCase):
    """
    Replays representative traffic mixes to guard against counter or
    percentage regressions introduced by future refactors.
    """

    def test_mixed_traffic_regression(self):
        clf = TrafficClassifier()
        mix = (
            [{"ip": True, "tcp":  True}] * 50 +
            [{"ip": True, "udp":  True}] * 30 +
            [{"ip": True, "icmp": True}] * 10 +
            [{"ip": False}]              * 10
        )
        _feed(clf, mix)

        self.assertEqual(clf.total_packets, 100)
        self.assertEqual(clf.protocol_count["TCP"],   50)
        self.assertEqual(clf.protocol_count["UDP"],   30)
        self.assertEqual(clf.protocol_count["ICMP"],  10)
        self.assertEqual(clf.protocol_count["OTHER"], 10)

        stats = clf.get_statistics()
        self.assertEqual(stats["protocols"]["TCP"]["percentage"],   50.0)
        self.assertEqual(stats["protocols"]["UDP"]["percentage"],   30.0)
        self.assertEqual(stats["protocols"]["ICMP"]["percentage"],  10.0)
        self.assertEqual(stats["protocols"]["OTHER"]["percentage"], 10.0)

    def test_all_other_traffic(self):
        clf = TrafficClassifier()
        _feed(clf, [{"ip": False}] * 20)
        self.assertEqual(clf.protocol_count["OTHER"], 20)
        stats = clf.get_statistics()
        self.assertEqual(stats["protocols"]["OTHER"]["percentage"], 100.0)

    def test_single_protocol_only(self):
        clf = TrafficClassifier()
        _feed(clf, [{"ip": True, "icmp": True}] * 7)
        self.assertEqual(clf.protocol_count["ICMP"], 7)
        self.assertEqual(clf.total_packets, 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)
