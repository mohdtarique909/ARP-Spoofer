"""Tests for the scanner and the ARP spoofing detector."""

from unittest import mock

import scapy.all as scapy

from arpspoofer import detect, scan


class TestScan:
    def test_scan_returns_sorted_devices(self):
        def make(ip, mac):
            r = mock.Mock()
            r.psrc, r.hwsrc = ip, mac
            return (mock.Mock(), r)

        answered = [make("192.168.1.10", "aa:.."), make("192.168.1.2", "bb:..")]
        with mock.patch.object(scan.scapy, "srp", return_value=(answered, [])):
            devices = scan.scan("192.168.1.0/24")

        assert [d["ip"] for d in devices] == ["192.168.1.2", "192.168.1.10"]

    def test_format_table_includes_count(self):
        out = scan.format_table([{"ip": "192.168.1.2", "mac": "bb:.."}])
        assert "192.168.1.2" in out
        assert "1 device(s) found." in out


class TestDetector:
    def _reply(self, ip, mac):
        return scapy.Ether() / scapy.ARP(op=2, psrc=ip, hwsrc=mac)

    def test_learns_first_binding_without_alert(self):
        w = detect.ArpWatcher()
        w.process(self._reply("192.168.1.1", "aa:aa:aa:aa:aa:aa"))
        assert w.alerts == 0
        assert w.table["192.168.1.1"] == "aa:aa:aa:aa:aa:aa"

    def test_flags_changed_mac_as_spoofing(self):
        w = detect.ArpWatcher()
        w.process(self._reply("192.168.1.1", "aa:aa:aa:aa:aa:aa"))
        w.process(self._reply("192.168.1.1", "de:ad:be:ef:00:01"))
        assert w.alerts == 1

    def test_ignores_arp_requests(self):
        w = detect.ArpWatcher()
        request = scapy.Ether() / scapy.ARP(op=1, psrc="192.168.1.1", hwsrc="aa:aa:aa:aa:aa:aa")
        w.process(request)
        assert w.table == {}
