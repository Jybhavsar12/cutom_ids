# Custom Intrusion Detection System (IDS)

## Overview

This project is a **Custom Intrusion Detection System (IDS)** built in Python. It captures live network traffic, analyzes packets for suspicious activity using both signature-based and anomaly-based detection methods, and logs alerts for potential security threats.

The IDS is designed to be modular, extensible, and easy to understand, making it a great showcase project for cybersecurity and Python programming skills.

---

## Features

- **Packet Capture:** Uses `scapy` to sniff live network packets.
- **Signature-Based Detection:** Detects known attack patterns such as SYN flood attempts.
- **Anomaly-Based Detection:** Detects unusual network behavior, e.g., unusually large packets.
- **Logging:** Alerts are logged to a file with timestamps for later analysis.
- **Modular Design:** Separate modules for detection logic, logging, and packet utilities.
- **Multi-threaded:** Runs signature and anomaly detection concurrently.

---


## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Jybhavsar12/custom_ids_project.git
   cd custom_ids_project

Installation
   pip install -r requirements.txt

USAGE
   sudo python ids.py

