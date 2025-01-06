# Firewall Sniffer

## Overview
The **Firewall Sniffer** is a Python-based firewall that dynamically inspects and filters network packets. It includes core functionalities such as IP blocking, port filtering, protocol filtering, whitelisting, and rate limiting. This project demonstrates practical cybersecurity concepts and serves as a learning tool for network security.

## Features
- **IP Filtering**: Block or allow traffic from specific IP addresses.
- **Port-Based Filtering**: Block packets targeting specific ports (e.g., HTTP, HTTPS).
- **Protocol-Based Filtering**: Block traffic based on protocols (e.g., ICMP, TCP, UDP).
- **Whitelist**: Trusted IPs bypass all filtering rules.
- **Dynamic Rule Updates**: Real-time updates using a JSON configuration file.
- **Rate Limiting**: Prevents abuse by limiting packet frequency per IP.
- **Logging**: Logs details of blocked packets for analysis.

## Project Structure
- `firewall_sniffer.py`: The main Python script for the firewall.
- `firewall_config.json`: Configuration file to define firewall rules.
- `firewall_log.txt`: Log file where blocked packets are recorded.
- `README.md`: Documentation file.
- `.gitignore`: Specifies files to exclude from the repository.

## Requirements
- **Python Version**: Python 3.7 or higher
- **Dependencies**:
  - `scapy`
- Install the dependencies using:
  ```bash
  pip install scapy
