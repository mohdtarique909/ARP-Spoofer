# ARP Spoofer

This project is an ARP spoofing tool that can be used to intercept network traffic by sending forged ARP messages. The tool is written in Python and uses the Scapy library to create and send the ARP packets.

## Requirements

- Python 3.x
- Scapy

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/yourusername/arp-spoofer.git
    cd arp-spoofer
    ```

2. Install the required Python libraries:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Run the ARP Spoofer script:

    ```bash
    python arp_spoofer.py
    ```

2. Enter the target IP and the gateway/router IP when prompted.

    ```plaintext
    Enter the Target IP: 192.168.1.10
    Enter the Gateway/Router IP: 192.168.1.1
    ```

3. The tool will start sending spoofed ARP packets, redirecting the target's traffic through your machine.

4. To stop the tool, press `CTRL + C`. The ARP tables will be restored to their original state.