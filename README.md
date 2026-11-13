# VoolDPI

A lightweight, low-level anti-DPI (Deep Packet Inspection) packet manipulation and segment splitting engine written in Python.

## 🚀 Overview

**VoolDPI** is designed to bypass modern Deep Packet Inspection (DPI) systems by intercepting network traffic at the transport layer and applying real-time TCP segment fragmentation. By splitting the Client Hello packet of the TLS handshake, it prevents censorship systems from properly analyzing the SNI (Server Name Indication), ensuring unhindered and private network access.

## 🛠️ Architecture & Mechanism

* **NetfilterQueue Integration:** Intercepts raw packets directly from kernel space (`iptables`).
* **SNI Parsing:** Automatically inspects TLS payloads to locate and extract domain information.
* **TCP Segment Splitting:** Dynamically fragments the packet payload (e.g., at a 30% ratio) and recalculates all necessary IP/TCP checksums and sequence numbers before re-injecting them via `scapy`.
* **State Management:** Tracks active TCP flows to avoid redundant processing and ensure connection stability.

## 📋 Requirements

* Linux (Tested on Fedora & Debian-based distributions)
* Python 3.x
* `netfilterqueue` library
* `scapy` library

## ⚙️ Usage

1. Configure your system firewall (`iptables`) to route traffic through the queue.
2. Run the script with elevated privileges:

```bash
sudo python3 VoolDpi.py


⚠️ Disclaimer

This tool iseated for educational purposes, network research, and understanding protocol-level packet manipulation. Users are responsible for complying with local laws and network policies.
