# SSH Abuse Detection Lab (SOC / Blue Team Project)

A custom SSH attack detection system that identifies brute force attacks,
credential abuse, baseline anomalies, and SSH tunnel activity, with alerts
ingested into **Wazuh SIEM** and automated response enabled.

This project demonstrates real-world **SOC detection engineering** using
live attacker traffic from Kali Linux.

---

## Overview

This lab simulates real SSH attacks against an Ubuntu server and detects
malicious behaviour using a custom Python-based detection engine.

The system analyses SSH authentication logs, correlates activity within a
time window, scores suspicious behaviour, maps detections to **MITRE ATT&CK**,
and forwards structured alerts to **Wazuh SIEM**.  
High-severity threats trigger automated containment actions.

---

## Lab Architecture

- **Attacker**: Kali Linux (bridged network)
- **Defender**: Ubuntu Server with SSH enabled
- **SIEM**: Wazuh (Manager, Indexer, Dashboard)
- **Detection Engine**: Custom Python scripts

Kali (Attacker)
│
└── SSH traffic
↓
Ubuntu (SSH Detector)
│
└── JSONL alerts
↓
Wazuh SIEM (Dashboard & Alerts)


---

## Threat Scenarios Detected

### 1. SSH Brute Force
Detects repeated failed SSH login attempts within a short time window.

**MITRE ATT&CK**
- T1110 – Brute Force
- T1021.004 – Remote Services: SSH

---

### 2. Credential Abuse (Failures → Success)
Identifies successful SSH authentication following multiple failed attempts,
indicating compromised credentials.

**MITRE ATT&CK**
- T1078 – Valid Accounts
- T1021.004 – Remote Services: SSH

---

### 3. Baseline Anomalies
Flags deviations from normal behaviour, such as:
- Login outside typical hours
- Login from a new IP range

**MITRE ATT&CK**
- T1078 – Valid Accounts

---

### 4. SSH Tunnel / Long-Lived Session Detection
Detects active SSH sessions with little or no recent authentication activity,
indicating possible tunnelling or persistence.

Uses live system state (`ss`) in addition to log analysis.

**MITRE ATT&CK**
- T1572 – Protocol Tunneling
- T1021.004 – Remote Services: SSH

---

## Detection Logic (High Level)

- Parses `/var/log/auth.log`
- Applies a rolling time window (default: 2 minutes)
- Correlates:
  - Failed login attempts
  - Successful logins after failures
  - Baseline deviations
  - Active SSH session state
- Assigns a score and severity based on risk

### Severity Model

| Score Range | Severity |
|------------|----------|
| 0–39 | LOW |
| 40–69 | MEDIUM |
| 70–89 | HIGH |
| 90–100 | CRITICAL |

Each alert includes a reconstructed attack timeline.

---

## Automated Response

- High and critical alerts trigger **automatic IP blocking**
- Uses `iptables` to simulate SOC containment actions
- Prevents continued attacker access after detection

---

## SIEM Integration (Wazuh)

- Alerts are written in **JSON Lines (JSONL)** format
- Wazuh ingests alerts via `localfile` log collection
- Custom Wazuh rules map detector severity to alert levels
- Alerts appear in the Wazuh dashboard with MITRE tagging

---

## Project Structure

ssh-abuse-detector/
├── src/
│ ├── detector.py # Core detection logic
│ ├── parser.py # SSH log parsing
│ ├── responder.py # Automated response (iptables)
│ └── mitre.py # MITRE ATT&CK mapping
├── data/
│ └── baseline.json # User login baselines
├── alerts/
│ └── ssh_detector.jsonl # SIEM-ready alert output
├── dashboard/
│ └── latest.csv # Lightweight alert summary
└── README.md


---

## Skills Demonstrated

- SOC detection engineering
- SSH log analysis and correlation
- MITRE ATT&CK mapping
- SIEM integration (Wazuh)
- Incident scoring and prioritisation
- Automated response and containment
- Linux security and SSH internals

---

## Disclaimer

This project is intended for **educational and defensive security purposes only**.

