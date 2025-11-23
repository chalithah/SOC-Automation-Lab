# 🛡️ End-to-End SOC Automation Project

## 🚀 Executive Summary
This project demonstrates the design and implementation of a fully automated **Security Operations Center (SOC) pipeline**. I built a virtualized home lab to simulate a real-world enterprise defense workflow. The system detects cyber threats, orchestrates enrichment using Threat Intelligence, manages cases via a ticketing system, and utilizes local Generative AI for incident analysis.

**The Goal:** To simulate a modern SOC environment, focusing on eliminating alert fatigue and drastically reducing Mean Time to Respond (MTTR) by automating Tier 1 Analyst tasks.

### 🏗️ Architecture & Technologies
* **Endpoint:** Windows 10 (Target Machine) + Sysmon
* **SIEM:** Splunk Enterprise (Log Management & Detection)
* **SOAR:** n8n (Workflow Automation)
* **Threat Intel:** AbuseIPDB & VirusTotal (Enrichment)
* **Case Management:** DFIR-IRIS
* **AI Analyst:** OpenAI (Triage) & Claude MCP (Chat-based Log Analysis)
* **Command & Control:** Atomic Red Team (Attack Simulation)

---

## 📸 Project Walkthrough

### 1. Lab Setup & Infrastructure
I established a secure virtualized lab environment using **VMware Workstation Pro**, hosting a Kali Linux attacker machine, a Windows 10 target, and an Ubuntu Server for the security stack.
* Configured `inputs.conf` on the Splunk Universal Forwarder to ingest Sysmon, Application, Security, and System logs.

![VMware Setup](screenshots/vmware-setup.png)
*Fig 1: The multi-OS virtualized lab environment.*

---

### 2. Attack Simulation & Detection Engineering
To validate the pipeline, I simulated a **Credential Dumping** attack (MITRE T1003) using **Atomic Red Team** and developed a custom detection rule to catch it.

#### **The Attack (Red Team)**
I executed `Invoke-AtomicTest T1059.001` (Mimikatz) on the Windows 10 endpoint. This script attempts to dump memory to extract plaintext passwords, simulating a common adversary technique.

![Attacker Execution](screenshots/attacker-mimikatz-execution.png)
*Fig 2: PowerShell output showing the successful execution of the Mimikatz simulation.*

#### **The Detection (Blue Team)**
I configured a Splunk alert to ingest PowerShell Operational logs and identify the specific signature of this attack.

**Splunk Processing Language (SPL):**
```splunk
index=mydfir-project "invoke-mimikatz" EventCode=4104 source="*PowerShell/Operational*"
| stats count min(_time) as first_seen max(_time) as last_seen by user, ComputerName
| sort - count
