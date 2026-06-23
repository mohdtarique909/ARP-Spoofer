"""Tests for spoof/restore packet construction with scapy mocked."""

from unittest import mock

import scapy.all as scapy

from arpspoofer import spoof


class TestSpoof:
    def test_spoof_sends_l2_arp_reply_with_correct_fields(self):
        with mock.patch.object(spoof.scapy, "sendp") as sendp, mock.patch.object(
            spoof, "get_mac", return_value="aa:bb:cc:dd:ee:ff"
        ):
            result = spoof.spoof("192.168.1.5", "192.168.1.1")

        assert result == "aa:bb:cc:dd:ee:ff"
        sent_packet = sendp.call_args.args[0]
        # Frame is addressed to the victim at Layer 2 so only they receive it.
        assert sent_packet[scapy.Ether].dst == "aa:bb:cc:dd:ee:ff"
        arp = sent_packet[scapy.ARP]
        assert arp.op == 2                  # ARP reply
        assert arp.pdst == "192.168.1.5"
        assert arp.psrc == "192.168.1.1"
        assert arp.hwdst == "aa:bb:cc:dd:ee:ff"

    def test_spoof_aborts_when_target_unreachable(self):
        with mock.patch.object(spoof.scapy, "sendp") as sendp, mock.patch.object(
            spoof, "get_mac", return_value=None
        ):
            assert spoof.spoof("10.0.0.9", "10.0.0.1") is None
            sendp.assert_not_called()  # no packet built from a None MAC

    def test_spoof_reuses_supplied_mac_without_lookup(self):
        with mock.patch.object(spoof.scapy, "sendp"), mock.patch.object(
            spoof, "get_mac"
        ) as get_mac:
            spoof.spoof("192.168.1.5", "192.168.1.1", target_mac="de:ad:be:ef:00:01")
            get_mac.assert_not_called()


class TestRestore:
    def test_restore_skips_when_mac_missing(self):
        with mock.patch.object(spoof.scapy, "sendp") as sendp, mock.patch.object(
            spoof, "get_mac", return_value=None
        ):
            assert spoof.restore("192.168.1.5", "192.168.1.1") is False
            sendp.assert_not_called()

    def test_restore_sends_when_both_macs_resolve(self):
        with mock.patch.object(spoof.scapy, "sendp") as sendp, mock.patch.object(
            spoof, "get_mac", return_value="aa:bb:cc:dd:ee:ff"
        ):
            assert spoof.restore("192.168.1.5", "192.168.1.1") is True
            sendp.assert_called_once()
