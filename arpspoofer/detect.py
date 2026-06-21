"""Real-time ARP spoofing detection.

Watches ARP replies on the wire and raises an alert when a single IP suddenly
maps to a new MAC address - the tell-tale sign of cache poisoning. This is the
defensive counterpart to spoof.py.
"""

import logging

import scapy.all as scapy

log = logging.getLogger("arpspoofer")


class ArpWatcher:
    """Tracks the IP->MAC bindings it has seen and flags conflicts."""

    def __init__(self):
        # ip -> mac, the first (assumed legitimate) binding we observed.
        self.table = {}
        self.alerts = 0

    def process(self, packet):
        if not packet.haslayer(scapy.ARP):
            return
        arp = packet[scapy.ARP]
        if arp.op != 2:  # only inspect ARP replies ("is-at")
            return

        ip = arp.psrc
        mac = arp.hwsrc
        known = self.table.get(ip)

        if known is None:
            self.table[ip] = mac
            log.debug("Learned %s is at %s", ip, mac)
        elif known != mac:
            self.alerts += 1
            log.warning(
                "POSSIBLE ARP SPOOFING: %s changed from %s to %s",
                ip,
                known,
                mac,
            )
            # Keep the latest binding so we don't spam on every packet.
            self.table[ip] = mac


def run(iface=None, count=0):
    """Sniff ARP traffic and report spoofing. count=0 means run until Ctrl+C."""
    watcher = ArpWatcher()
    log.info("Listening for ARP spoofing on %s (Ctrl+C to stop)...", iface or "default iface")
    try:
        scapy.sniff(
            iface=iface,
            store=False,
            filter="arp",
            prn=watcher.process,
            count=count,
        )
    except KeyboardInterrupt:
        pass
    log.info("Stopped. %d alert(s) raised across %d host(s).", watcher.alerts, len(watcher.table))
    return 0
