"""Network discovery: find live hosts on a subnet with their IP and MAC."""

import logging

import scapy.all as scapy

from .utils import BROADCAST_MAC

log = logging.getLogger("arpspoofer")


def scan(network, iface=None, timeout=2):
    """ARP-scan a network/CIDR and return a list of {'ip', 'mac'} dicts."""
    request = scapy.Ether(dst=BROADCAST_MAC) / scapy.ARP(pdst=network)
    answered = scapy.srp(request, timeout=timeout, iface=iface, verbose=False)[0]

    devices = [{"ip": rcv.psrc, "mac": rcv.hwsrc} for _, rcv in answered]
    devices.sort(key=lambda d: tuple(int(o) for o in d["ip"].split(".")))
    return devices


def format_table(devices):
    """Render discovered devices as an aligned text table."""
    lines = [
        "-" * 40,
        f"{'IP Address':<18}{'MAC Address':<18}",
        "-" * 40,
    ]
    for d in devices:
        lines.append(f"{d['ip']:<18}{d['mac']:<18}")
    lines.append("-" * 40)
    lines.append(f"{len(devices)} device(s) found.")
    return "\n".join(lines)


def run(network, iface=None, timeout=2):
    log.info("Scanning %s ...", network)
    devices = scan(network, iface=iface, timeout=timeout)
    print(format_table(devices))
    return 0
