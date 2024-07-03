# ARP Spoofer

This project is an ARP spoofing tool that can be used to intercept network traffic by sending forged ARP messages. The tool is written in Python and uses the Scapy library to create and send the ARP packets.

## Requirements

- Python 3.x
- Scapy

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/mohdtarique909/ARP-Spoofer.git
    cd arp-spoofer
    ```

2. Install the required Python libraries:

    ```bash
    pip install -r requirements.txt
    ```

## Usage


1. Enable IP forwarding to allow your machine to forward packets:

    ```bash
    echo 1 > /proc/sys/net/ipv4/ip_forward
    ```

2. Run the ARP Spoofer script:

    ```bash
    python arp_spoofer.py
    ```

3. Enter the target IP and the gateway/router IP when prompted.

    ```plaintext
    Enter the Target IP: 192.168.1.10
    Enter the Gateway/Router IP: 192.168.1.1
    ```

4. The tool will start sending spoofed ARP packets, redirecting the target's traffic through your machine.

5. To stop the tool, press `CTRL + C`. The ARP tables will be restored to their original state.


## Disclaimer

This tool is for educational purposes only. Use it at your own risk. The author is not responsible for any misuse or damage caused by this tool.