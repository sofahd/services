# SOFAH Services Module

This repository contains the Services module for the SOFAH (Speedy Open Framework for Automated Honeypot-development) project, which includes the implementation of various services essential for the operation of SOFAH honeypots. These services are crucial for emulating realistic network environments and capturing interactions with potential threats.

## Services Overview

The SOFAH Services module comprises several key services, each responsible for a specific aspect of the honeypot framework:

- **API Honeypot (`api_honeypot.py`)**: Simulates API endpoints to capture and analyze requests from potential attackers.
- **ENNORM (`ennorm.py`)**: The ENrichment NORMalization module that processes data to automatically configure and deploy services.
- **Log API (`log_api.py`)**: Collects and aggregates log data from all services, facilitating analysis and monitoring.
- **Nginx Honeypot (`nginx_honeypot.py`)**: Acts as a reverse proxy to direct traffic to appropriate honeypots based on request details.
- **Port Spoof (`port_spoof.py`)**: Emulates open ports and services to deceive scanners and attackers.
- **Recon (`recon.py`)**: Conducts reconnaissance to gather information on potential targets for the honeypot to simulate.


