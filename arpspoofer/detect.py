"""Real-time ARP spoofing detection.

Two complementary modes:

* sniff mode (default) watches ARP replies on the wire and alerts when a single
  IP suddenly maps to a new MAC - the tell-tale sign of cache poisoning.
* cache mode (--watch-cache) polls the operating system's own ARP cache and
  alerts on the same binding changes. This catches attacks the sniffer can miss
  on Wi-Fi/Windows, where Npcap often does not surface the incoming unicast
  poison frame even though the OS still updates its cache.

This is the defensive counterpart to spoof.py.
"""

import logging
import re
import subprocess
import sys
import time

import scapy.all as scapy

log = logging.getLogger("arpspoofer")

# IP and MAC patterns shared by every OS's ARP-cache command output.
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_MAC_RE = re.compile(r"\b((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})\b")

# MACs that are not a real host binding (broadcast / multicast / unset).
_IGNORED_MAC_PREFIXES = ("ff:ff:ff", "01:00:5e", "33:33:", "00:00:00:00:00:00")


def _normalise_mac(mac):
    """Lower-case and colon-separate a MAC so '40-C7-3C' == '40:c7:3c'."""
    return mac.replace("-", ":").lower()


class ArpWatcher:
    """Tracks the IP->MAC bindings it has seen and flags conflicts.

    The learn/alert logic in update() is shared by both detection modes.
    """

    def __init__(self):
        # ip -> mac, the first (assumed legitimate) binding we observed.
        self.table = {}
        self.alerts = 0

    def update(self, ip, mac):
        """Record an IP->MAC binding, alerting if it conflicts with the first."""
        mac = _normalise_mac(mac)
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

    def process(self, packet):
        """Feed a sniffed packet; only ARP replies ("is-at") are inspected."""
        if not packet.haslayer(scapy.ARP):
            return
        arp = packet[scapy.ARP]
        if arp.op != 2:  # only inspect ARP replies ("is-at")
            return
        self.update(arp.psrc, arp.hwsrc)


def read_arp_cache():
    """Return the OS ARP cache as {ip: mac}, normalised to lower-case colons.

    Works across Windows (`arp -a`), Linux (`ip neigh` / `arp -an`) and macOS
    (`arp -an`). Broadcast and multicast entries are skipped.
    """
    if sys.platform == "win32":
        commands = [["arp", "-a"]]
    else:
        commands = [["ip", "neigh", "show"], ["arp", "-an"]]

    output = None
    for cmd in commands:
        try:
            output = subprocess.run(
                cmd, capture_output=True, text=True, check=True
            ).stdout
            break
        except (OSError, subprocess.CalledProcessError):
            continue

    if output is None:
        log.error("Could not read the OS ARP cache (no working arp/ip command).")
        return {}

    cache = {}
    for line in output.splitlines():
        ip_match = _IP_RE.search(line)
        mac_match = _MAC_RE.search(line)
        if not ip_match or not mac_match:
            continue
        mac = _normalise_mac(mac_match.group(1))
        if mac.startswith(_IGNORED_MAC_PREFIXES):
            continue
        cache[ip_match.group(1)] = mac
    return cache


def _watch_cache(interval=2, count=0):
    """Poll the OS ARP cache and alert on binding changes. count = max polls."""
    watcher = ArpWatcher()
    log.info(
        "Watching the OS ARP cache for spoofing (polling every %ss, Ctrl+C to stop)...",
        interval,
    )
    polls = 0
    try:
        while True:
            for ip, mac in read_arp_cache().items():
                watcher.update(ip, mac)
            polls += 1
            if count and polls >= count:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    log.info(
        "Stopped. %d alert(s) raised across %d host(s).", watcher.alerts, len(watcher.table)
    )
    return 0


def _sniff(iface=None, count=0):
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


def run(iface=None, count=0, watch_cache=False, interval=2):
    """Detect ARP spoofing by sniffing the wire, or by polling the OS ARP cache.

    With watch_cache=True, `count` is the number of polls (0 = forever) and
    `interval` is the seconds between them; otherwise `count` is the number of
    packets to sniff (0 = forever).
    """
    if watch_cache:
        return _watch_cache(interval=interval, count=count)
    return _sniff(iface=iface, count=count)
