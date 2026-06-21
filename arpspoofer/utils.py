"""Shared helpers: logging, IP validation, MAC resolution, IP forwarding."""

import ipaddress
import logging
import platform
import subprocess
import sys

import scapy.all as scapy

log = logging.getLogger("arpspoofer")

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def setup_logging(verbose=False, logfile=None):
    """Configure the package logger. Console always on; file optional."""
    level = logging.DEBUG if verbose else logging.INFO
    log.setLevel(level)
    log.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    log.addHandler(console)

    if logfile:
        file_handler = logging.FileHandler(logfile)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        log.addHandler(file_handler)
    return log


def valid_ip(value):
    """Return the normalised IP string, or raise ValueError for argparse."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError(f"'{value}' is not a valid IP address")


def valid_network(value):
    """Validate a CIDR network (e.g. 192.168.1.0/24) for argparse."""
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise ValueError(f"'{value}' is not a valid network (use CIDR, e.g. 192.168.1.0/24)")


def get_mac(ip, iface=None, timeout=2, retries=2):
    """Resolve the MAC address for an IP via an ARP request.

    Returns the MAC string, or None if the host did not answer. Unlike the
    naive version this retries and never lets an empty response raise.
    """
    request = scapy.Ether(dst=BROADCAST_MAC) / scapy.ARP(pdst=ip)
    for attempt in range(1, retries + 1):
        answered = scapy.srp(request, timeout=timeout, iface=iface, verbose=False)[0]
        if answered:
            return answered[0][1].hwsrc
        log.debug("No ARP reply for %s (attempt %d/%d)", ip, attempt, retries)
    log.warning("Could not resolve MAC for %s - host may be down or unreachable", ip)
    return None


def set_ip_forwarding(enabled):
    """Enable or disable IP forwarding so we relay (not drop) victim traffic.

    Returns True on success. Cross-platform best-effort: Linux and macOS are
    handled; on Windows we warn and let the user configure it manually.
    """
    system = platform.system()
    value = "1" if enabled else "0"
    try:
        if system == "Linux":
            with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
                fh.write(value + "\n")
        elif system == "Darwin":  # macOS
            subprocess.run(
                ["sysctl", "-w", f"net.inet.ip.forwarding={value}"],
                check=True,
                capture_output=True,
            )
        else:
            log.warning(
                "IP forwarding must be enabled manually on %s; victim traffic "
                "will be dropped (denial of service) without it.",
                system,
            )
            return False
        log.info("IP forwarding %s", "enabled" if enabled else "disabled")
        return True
    except (PermissionError, OSError, subprocess.CalledProcessError) as exc:
        log.error("Failed to toggle IP forwarding (need root?): %s", exc)
        return False
