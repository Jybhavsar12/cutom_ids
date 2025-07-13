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

## Directory Structure
custom_ids_project/
│
├── README.md                  # Project overview, setup, usage instructions
├── requirements.txt           # Python dependencies (e.g., scapy, pandas, sklearn)
├── ids.py                     # Main script to start the IDS
│
├── config/
│   └── settings.py            # Configuration variables (thresholds, logging settings)
│
├── detectors/
│   ├── __init__.py            # Makes this a Python package
│   ├── signature_detector.py  # Signature-based detection logic (e.g., SYN flood)
│   ├── anomaly_detector.py    # Anomaly detection logic (feature extraction, ML)
│
├── utils/
│   ├── __init__.py
│   ├── logger.py              # Logging setup and helper functions
│   └── packet_utils.py        # Packet parsing and feature extraction functions
│
├── data/
│   ├── training_data.csv      # (Optional) Dataset for anomaly detection training
│   └── ids_alerts.log         # Log file for alerts (can be generated at runtime)
│
└── tests/
    ├── __init__.py
    ├── test_signature_detector.py
    ├── test_anomaly_detector.py
    └── test_packet_utils.py


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

