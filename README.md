# 🛡️ End-to-End SOC Automation Project

## 🚀 Executive Summary

This project demonstrates the design and implementation of a fully automated Security Operations Center (SOC) pipeline. I built a virtualized environment to simulate a real-world enterprise defense workflow. The system detects cyber threats, orchestrates enrichment using Threat Intelligence, manages cases via a ticketing system, and utilizes local Generative AI for incident analysis.

**The Goal:** To simulate a modern SOC environment, focusing on eliminating alert fatigue and drastically reducing Mean Time to Respond (MTTR) by automating Tier 1 Analyst tasks.

---

## 🏗️ Architecture & Technologies

- **Endpoint:** Windows 10 (Target Machine) + Sysmon
- **SIEM:** Splunk Enterprise (Log Management & Detection)
- **SOAR:** n8n (Workflow Automation)
- **Threat Intel:** AbuseIPDB & VirusTotal (Enrichment)
- **Case Management:** DFIR-IRIS
- **AI Analyst:** OpenAI (Triage) & Claude MCP (Chat-based Log Analysis)
- **Command & Control:** Atomic Red Team (Attack Simulation)

---

## 📸 Project Walkthrough

### 1. Lab Setup & Infrastructure

I established a secure virtualized lab environment using VMware Workstation Pro, hosting a Kali Linux attacker machine, a Windows 10 target, and an Ubuntu Server for the security stack.

Configured `inputs.conf` on the Splunk Universal Forwarder to ingest Sysmon, Application, Security, and System logs.

*Fig 1: The multi-OS virtualized lab environment.*

---

### 2. Attack Simulation & Detection Engineering

To validate the pipeline, I simulated a Credential Dumping attack (MITRE T1003) using Atomic Red Team and developed a custom detection rule to catch it.

**The Attack (Red Team):** I executed `Invoke-AtomicTest T1059.001` (Mimikatz) on the Windows 10 endpoint. This script attempts to dump memory to extract plaintext passwords, simulating a common adversary technique.

*Fig 2: PowerShell output showing the successful execution of the Mimikatz simulation.*

**The Detection (Blue Team):** I configured a Splunk alert to ingest PowerShell Operational logs and identify the specific signature of this attack.

**Splunk Processing Language (SPL):**

```spl
index=mydfir-project "invoke-mimikatz" EventCode=4104 source="*PowerShell/Operational*"
| stats count min(_time) as first_seen max(_time) as last_seen by user, ComputerName
| sort - count
```

*Fig 3: Verifying that Splunk successfully ingested the Mimikatz execution logs.*

**Alert Configuration & Logic:** I configured the alert with specific keywords (`invoke-mimikatz`), source filtering (`PowerShell/Operational`), and a 24-hour throttle. This reduces false positives while ensuring real Mimikatz attacks are detected and reported immediately without flooding the analyst with duplicate tickets.

I set the severity to HIGH because Mimikatz is a critical threat tool used for credential extraction. This ensures the automation pipeline treats it as an urgent incident requiring immediate AI analysis.

*Fig 4: Tuning the alert logic to prevent alert fatigue while maintaining high severity for critical threats.*

---

### 3. Orchestration & Automation (n8n)

I deployed n8n via Docker to orchestrate the incident response workflow. This acts as the "glue" connecting the different security tools.

- **Enrichment:** The workflow extracts IPs and Hashes and queries VirusTotal/AbuseIPDB.
- **AI Analysis:** It pushes the data to an LLM (OpenAI) to generate a human-readable summary and recommended actions.

*Fig 5: The complete automation workflow: Webhook -> Enrichment -> AI Analysis -> Response.*

**The Deliverable:** The automation bot posts a structured alert to Slack, allowing the SOC team to see the threat summary, enrichment data, and severity without logging into the SIEM.

*Fig 6: The final alert delivered to the analyst, featuring the AI-generated summary and recommendations.*

---

### 4. Case Management (DFIR-IRIS)

To move beyond simple alerting, I integrated DFIR-IRIS for formal case tracking.

Configured the n8n workflow to map JSON alert data directly into the IRIS database via API.

This ensures an immutable audit trail is created for every detected incident.

*Fig 7: Automated ticket creation in the IRIS Case Management platform with IOC enrichment populated.*

---

### 5. Advanced AI Integration (Claude MCP)

As an advanced feature, I implemented the Model Context Protocol (MCP) to bridge Claude Desktop with my local Splunk instance. This enables "Chat with your Data" capabilities.

**Infrastructure as Code:** I configured the `claude_desktop_config.json` to allow the LLM to execute Python scripts securely against the Splunk API.

*Fig 8: Configuring the JSON bridge between the LLM and the local Splunk server.*

*Fig 9: Verifying the local MCP server is running and connected.*

**The AI Analyst:** I can now ask Claude natural language questions like "Show me suspicious activity from the last hour," and the AI generates the SPL, queries the database, and summarizes the results without me writing code.

*Fig 10: The AI Agent independently querying Splunk and summarizing the Credential Dumping attack.*

---

## 🏆 Skills Demonstrated

- **SIEM Administration:** Log parsing, Universal Forwarder configuration, and SPL querying.
- **Detection Engineering:** Tuning alerts to reduce false positives and assigning appropriate risk scores.
- **SOAR Development:** Building API-based workflows and handling JSON data structures.
- **Infrastructure:** Docker container management, Linux CLI administration, and VMware networking.
- **AI Engineering:** Implementing local LLM integrations via Model Context Protocol (MCP).
- **Threat Intelligence:** Automating reputation checks via APIs.
