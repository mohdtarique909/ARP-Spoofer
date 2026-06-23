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

    def test_treats_dashed_uppercase_mac_as_same_binding(self):
        # Windows `arp -a` prints 40-C7-3C..., the wire gives 40:c7:3c... - the
        # detector must not mistake the same MAC in two notations for a change.
        w = detect.ArpWatcher()
        w.update("192.168.1.1", "40-C7-3C-14-61-AD")
        w.update("192.168.1.1", "40:c7:3c:14:61:ad")
        assert w.alerts == 0


class TestArpCacheReader:
    WINDOWS_OUT = (
        "Interface: 10.207.187.101 --- 0x8\n"
        "  Internet Address      Physical Address      Type\n"
        "  10.207.187.109        b2-9d-c6-1f-7d-5a     dynamic\n"
        "  10.207.187.255        ff-ff-ff-ff-ff-ff     static\n"
        "  224.0.0.22            01-00-5e-00-00-16     static\n"
    )
    LINUX_OUT = "10.207.187.109 dev wlan0 lladdr b2:9d:c6:1f:7d:5a REACHABLE\n"

    def _patch_run(self, stdout):
        result = mock.Mock(stdout=stdout)
        return mock.patch.object(detect.subprocess, "run", return_value=result)

    def test_parses_windows_output_and_skips_bcast_mcast(self):
        with self._patch_run(self.WINDOWS_OUT):
            cache = detect.read_arp_cache()
        assert cache == {"10.207.187.109": "b2:9d:c6:1f:7d:5a"}

    def test_parses_linux_ip_neigh_output(self):
        with self._patch_run(self.LINUX_OUT):
            cache = detect.read_arp_cache()
        assert cache == {"10.207.187.109": "b2:9d:c6:1f:7d:5a"}

    def test_watch_cache_alerts_when_binding_changes(self, caplog):
        # First poll learns the real MAC; second poll sees the poisoned one.
        polls = [
            {"10.207.187.109": "b2:9d:c6:1f:7d:5a"},
            {"10.207.187.109": "08:00:27:10:51:1d"},
        ]
        with mock.patch.object(detect, "read_arp_cache", side_effect=polls), \
                mock.patch.object(detect.time, "sleep"), \
                caplog.at_level("WARNING", logger="arpspoofer"):
            rc = detect.run(watch_cache=True, count=2, interval=0)
        assert rc == 0
        assert "POSSIBLE ARP SPOOFING" in caplog.text
