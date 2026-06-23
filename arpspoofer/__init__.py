"""arpspoofer - an educational ARP cache-poisoning toolkit.

Provides five capabilities:
  * spoof   - perform a man-in-the-middle ARP cache poisoning attack
  * detect  - sniff the LAN and alert on ARP spoofing in real time
  * scan    - discover live hosts on the network (IP + MAC)
  * sniff   - capture plaintext HTTP traffic flowing through the MITM
  * restore - rebuild a victim's ARP table to its legitimate state

For authorized testing and education only. See README for the legal notice.
"""

__version__ = "1.0.0"
