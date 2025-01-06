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
  ```
## Configuration
Edit the `firewall_config.json` file to define your custom rules:
```bash
{
    "whitelisted_ips": ["127.0.0.1", "192.168.1.50"],
    "blocked_ips": ["192.168.1.100"],
    "blocked_ports": [80, 443],
    "blocked_protocols": ["ICMP"]
}
```
## Usage
1. Run the firewall:
   ```bash
   python firewall_sniffer.py
2. Dynamic Rules Update
   - Modify `firewall_config.json` to add or remove rules while the firewall is running.
3. Generate Traffic Using:
   - `ping`
   - `curl`
   - `hping3`

## Testing
- Whitelist Test: Verify that traffic from IPs in whitelisted_ips bypasses all filters.
- Rate Limit Test: Generate excess traffic from a single IP to trigger the rate-limiting mechanism.
- Ports and Protocols Test: Confirm that blocked protocols and ports are handled correctly.

## Logs
- Blocked packets are recorded in firewall_logs.txt in the following format:
  ``` bash
  Blocked: IP <SRC> -> <DST> | Reason: <Reason for block>
  ```

## License
This project is licensed under the MIT License. Feel free to use and modify for educational purposes.
  
     
