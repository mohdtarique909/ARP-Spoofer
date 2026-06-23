# ARP Spoofer Toolkit

A Python toolkit for understanding **Layer-2 (ARP) attacks and defenses**. It can
perform an ARP cache-poisoning man-in-the-middle (MITM) attack, **detect** that
same attack in real time, **discover** every device on a LAN, and **restore**
poisoned ARP tables to a clean state.

Built with [Scapy](https://scapy.net/). Designed as an attack **and** defense
project: the goal isn't just to break the protocol, but to show how to spot and
mitigate the attack — the mindset that matters in security work.

> ⚠️ **Legal & ethical notice.** Use this **only** on networks and devices you
> own or are explicitly authorized to test. ARP spoofing intercepts other
> people's traffic; running it on networks you don't control is illegal in most
> jurisdictions. You are responsible for your own actions.

---

## What it does

| Mode | Description |
|------|-------------|
| `scan` | Discover live hosts on a subnet with their IP and MAC address (ARP sweep). |
| `spoof` | MITM a victim and the gateway via ARP cache poisoning, auto-managing IP forwarding and cleaning up on exit. |
| `sniff` | Capture plaintext HTTP requests (URLs and possible credentials) flowing through you while you're the MITM. |
| `detect` | Alert when one IP suddenly maps to a new MAC — the signature of poisoning. Watches the wire by default, or the OS ARP cache with `--watch-cache`. |
| `restore` | Manually rebuild two hosts' ARP tables (the attack also does this automatically on `Ctrl+C`). |

### The full attack chain

These modes compose into a realistic workflow — and its defense:

```
1. scan    →  find the victim and the gateway on the network
2. spoof   →  become the man in the middle (traffic now flows through you)
3. sniff   →  read the victim's plaintext HTTP traffic
   (HTTPS stays encrypted — that's the takeaway)
4. detect  →  the blue-team view: how a defender spots steps 2-3 in real time
```

---

## How ARP spoofing works

ARP has no authentication: a host believes any "is-at" reply it receives. The
attacker abuses this by sending forged replies to both the victim and the
gateway, inserting itself in the middle of their conversation.

```
   Normal traffic                       After ARP poisoning
   --------------                       -------------------
                                                 ┌──────────┐
   ┌────────┐      ┌────────┐                     │ Attacker │
   │ Victim │ ───► │ Router │            ┌──────► │ (MITM)   │ ──────┐
   └────────┘      └────────┘            │        └──────────┘       ▼
                                    ┌────────┐                  ┌────────┐
                                    │ Victim │                  │ Router │
                                    └────────┘ ◄────────────────└────────┘
        Victim and Router each think the Attacker's MAC is the other's.
```

For the attacker to remain a *man in the middle* (and not just black-hole the
traffic, which is a denial of service), the host must forward packets it
receives — so the tool enables **IP forwarding** automatically and turns it off
again on exit.

---

## Installation

```bash
git clone https://github.com/mohdtarique909/ARP-Spoofer.git
cd ARP-Spoofer
pip install -r requirements.txt        # or: pip install -e .
```

Scapy needs a packet-capture backend and root/admin privileges:

- **Linux/macOS:** run with `sudo`. libpcap is usually present.
- **Windows:** install [Npcap](https://npcap.com/) and run from an Administrator terminal.

---

## Usage

Run as a module (`python -m arpspoofer ...`) or, after `pip install -e .`, via the
`arpspoofer` command.

**Discover devices on your network:**
```bash
sudo python -m arpspoofer scan 192.168.1.0/24
```
```
----------------------------------------
IP Address        MAC Address
----------------------------------------
192.168.1.1       a4:2b:b0:11:22:33
192.168.1.5       de:ad:be:ef:00:01
192.168.1.20      f0:18:98:aa:bb:cc
----------------------------------------
3 device(s) found.
```

**Run the MITM attack** (IP forwarding is enabled/disabled for you):
```bash
sudo python -m arpspoofer spoof -t 192.168.1.5 -g 192.168.1.1 -i eth0
```
Press `Ctrl+C` to stop — the tool restores both ARP tables automatically.

**Sniff plaintext HTTP traffic** (while spoofing, in a second terminal):
```bash
sudo python -m arpspoofer sniff -i eth0
```
```
13:45:12 [INFO] HTTP POST http://example.com/login
13:45:12 [WARNING] Possible plaintext credentials >> username=admin&password=hunter2
```
Only unencrypted HTTP is readable — HTTPS traffic stays encrypted, which is the
point of the demonstration.

**Detect ARP spoofing on the network** (run on a victim/monitor machine):
```bash
sudo python -m arpspoofer detect -i eth0
```
```
13:42:07 [WARNING] POSSIBLE ARP SPOOFING: 192.168.1.1 changed from a4:2b:b0:11:22:33 to de:ad:be:ef:00:01
```

`detect` has two modes:

- **Sniff mode (default):** passively captures ARP replies off the wire and
  alerts on a changed binding.
- **Cache-watch mode (`--watch-cache`):** polls the operating system's own ARP
  table (`arp -a` / `ip neigh`) instead of capturing packets:

  ```bash
  python -m arpspoofer detect --watch-cache -v          # poll every 2s
  python -m arpspoofer detect --watch-cache --interval 1
  ```

  Use this on **Wi-Fi and Windows**, where the packet sniffer can miss the
  attack: the incoming unicast poison frame often isn't surfaced by Npcap even
  though the OS still updates its ARP cache. Cache-watch mode reads that cache
  directly, so it catches the change the sniffer doesn't see. Two caveats: it
  trusts the *first* binding it observes as legitimate (so start it on a clean
  cache), and it only checks every `--interval` seconds, so a brief
  poison-then-restore can slip between polls.

**Restore manually if needed:**
```bash
sudo python -m arpspoofer restore -t 192.168.1.5 -g 192.168.1.1
```

Global flags: `-v/--verbose` for debug logging, `--logfile FILE` to also log to a
file, `-i/--iface` to pick an interface.

---

## How to defend against ARP spoofing

The defensive half of this project. To protect a real network:

- **Dynamic ARP Inspection (DAI)** on managed switches validates ARP packets
  against a trusted DHCP-snooping table and drops forged ones.
- **Static ARP entries** for critical hosts (e.g. the gateway) so their MAC
  can't be overwritten by a reply.
- **Port security / 802.1X** to control which devices can join the network.
- **Encryption (HTTPS/TLS, VPN)** so that even if traffic is intercepted, it
  can't be read or modified.
- **Monitoring** — exactly what this tool's `detect` mode demonstrates: watch for
  an IP whose MAC suddenly changes (`arpwatch` does the same in production).

---

## Project layout

```
arpspoofer/
├── cli.py       # argparse CLI and command dispatch
├── spoof.py     # ARP poisoning attack + table restoration
├── sniff.py     # HTTP traffic sniffer + credential detection
├── detect.py    # real-time spoofing detector (wire sniff + ARP-cache watch)
├── scan.py      # network host discovery
└── utils.py     # logging, IP validation, MAC resolution, IP forwarding
tests/           # pytest suite (scapy mocked — no packets sent)
```

## Development

```bash
pip install -r requirements-dev.txt
pytest
```

The test suite mocks Scapy, so it runs anywhere without sending real packets or
needing privileges.

---

## License

MIT — see [LICENSE](LICENSE).
