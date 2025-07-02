# 🧠 Advanced Python Network Sniffer

A powerful command-line network sniffer written in Python using Scapy.  
It captures packets, filters them, logs details, and highlights key data.

---

## ✨ Features

- Live packet capturing with interface selection
- Supports filters like `tcp`, `udp`, `port 80`
- Displays:
  - Timestamps
  - MAC addresses
  - IP addresses
  - Protocols
  - Ports
  - Payload
- Logs every packet to `sniffer_log.txt`
- Pretty color-coded terminal output

---

## 🛠 Requirements

```bash
pip install -r requirements.txt
