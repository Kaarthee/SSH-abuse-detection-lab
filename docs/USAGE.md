# SSH Abuse Detector – Usage Guide

This document explains how to run and test the SSH Abuse Detection Lab.

---

## Running the Detector

From the project root:

```bash
sudo python3 src/detector.py
The detector analyses recent SSH activity and produces:

console alerts

JSONL alerts for SIEM ingestion

optional automated response

Alert Output
Each alert includes:

source IP

severity level

risk score

detected behaviours

MITRE ATT&CK techniques

reconstructed timeline

Example:

[CRITICAL] 192.168.20.18 | Score=90
Brute Force → Credential Abuse → Active SSH Session
Testing Scenarios
Brute Force
Repeated failed SSH logins within a short window.

Credential Abuse
Successful login following multiple failed attempts.

Tunnel / Persistence
Long-lived SSH sessions detected via live system state.

SIEM Integration
Alerts are written to:

alerts/ssh_detector.jsonl
This file is ingested by Wazuh using localfile JSON collection and mapped to
custom alert rules.

Automated Response
High-risk alerts trigger automatic IP blocking using iptables.

This simulates SOC containment actions in response to active threats.

Notes
Root privileges are required to read auth logs and manage firewall rules

Designed for educational and defensive security use only
