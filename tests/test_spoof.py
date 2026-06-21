"""Tests for spoof/restore packet construction with scapy mocked."""

from unittest import mock

from arpspoofer import spoof


class TestSpoof:
    def test_spoof_sends_arp_reply_with_correct_fields(self):
        with mock.patch.object(spoof.scapy, "send") as send, mock.patch.object(
            spoof, "get_mac", return_value="aa:bb:cc:dd:ee:ff"
        ):
            result = spoof.spoof("192.168.1.5", "192.168.1.1")

        assert result == "aa:bb:cc:dd:ee:ff"
        sent_packet = send.call_args.args[0]
        assert sent_packet.op == 2          # ARP reply
        assert sent_packet.pdst == "192.168.1.5"
        assert sent_packet.psrc == "192.168.1.1"
        assert sent_packet.hwdst == "aa:bb:cc:dd:ee:ff"

    def test_spoof_aborts_when_target_unreachable(self):
        with mock.patch.object(spoof.scapy, "send") as send, mock.patch.object(
            spoof, "get_mac", return_value=None
        ):
            assert spoof.spoof("10.0.0.9", "10.0.0.1") is None
            send.assert_not_called()  # no packet built from a None MAC

    def test_spoof_reuses_supplied_mac_without_lookup(self):
        with mock.patch.object(spoof.scapy, "send"), mock.patch.object(
            spoof, "get_mac"
        ) as get_mac:
            spoof.spoof("192.168.1.5", "192.168.1.1", target_mac="de:ad:be:ef:00:01")
            get_mac.assert_not_called()


class TestRestore:
    def test_restore_skips_when_mac_missing(self):
        with mock.patch.object(spoof.scapy, "send") as send, mock.patch.object(
            spoof, "get_mac", return_value=None
        ):
            assert spoof.restore("192.168.1.5", "192.168.1.1") is False
            send.assert_not_called()

    def test_restore_sends_when_both_macs_resolve(self):
        with mock.patch.object(spoof.scapy, "send") as send, mock.patch.object(
            spoof, "get_mac", return_value="aa:bb:cc:dd:ee:ff"
        ):
            assert spoof.restore("192.168.1.5", "192.168.1.1") is True
            send.assert_called_once()
