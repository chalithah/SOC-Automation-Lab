# End-to-End SOC Automation Project
![The complete automation workflow: Webhook → Enrichment → AI Analysis → Response.](https://github.com/chalithah/SOC-Automation-Lab/blob/fd8dbdc1d0849a68e5a169234a248d04f534b4a9/assets/images/n8n-workflow.png)

##  Summary

This project demonstrates the design and implementation of a fully automated Security Operations Center (SOC) pipeline. I built a virtualized environment to simulate a real-world enterprise defense workflow. The system detects cyber threats, orchestrates enrichment using Threat Intelligence, manages cases via a ticketing system, and utilizes local Generative AI for incident analysis.

**The Goal:** To simulate a modern SOC environment, focusing on eliminating alert fatigue and drastically reducing Mean Time to Respond (MTTR) by automating Tier 1 Analyst tasks.

---

##  Architecture & Technologies

- **Endpoint:** Windows 10 (Target Machine) + Sysmon
- **SIEM:** Splunk Enterprise (Log Management & Detection)
- **SOAR:** n8n (Workflow Automation)
- **Threat Intel:** AbuseIPDB & VirusTotal (Enrichment)
- **Case Management:** DFIR-IRIS
- **Alerting:** Slack notifications to the SOC team
- **AI Analyst:** OpenAI (Triage) & Claude MCP (Chat-based Log Analysis)
- **Command & Control:** Atomic Red Team (Attack Simulation)

---

##  Project Walkthrough

### 1. Lab Setup & Infrastructure

I established a secure virtualized lab environment using VMware Workstation Pro, hosting a Kali Linux attacker machine, a Windows 10 target, and an Ubuntu Server for the security stack.

Configured `inputs.conf` on the Splunk Universal Forwarder to ingest Sysmon, Application, Security, and System logs.

<p align="center">
  <img src="https://github.com/chalithah/SOC-Automation-Lab/blob/64f7623bf6de3a7317c74772a663b7c5bee5fe3c/assets/images/vmware-setup.png" width="600">
  <br>
  <em><b>Fig 1:</b> The multi-OS virtualized lab environment.</em>
</p>


---

### 2. Attack Simulation & Detection Engineering

To validate the pipeline, I simulated a Credential Dumping attack (MITRE T1003) using Atomic Red Team and developed a custom detection rule to catch it.

**The Attack (Red Team):** I executed `Invoke-AtomicTest T1059.001` (Mimikatz) on the Windows 10 endpoint. This script attempts to dump memory to extract plaintext passwords, simulating a common adversary technique.

<p align="center">
  <img src="https://github.com/chalithah/SOC-Automation-Lab/blob/64f7623bf6de3a7317c74772a663b7c5bee5fe3c/assets/images/attacker-mimikatz-execution.png" width="600">
  <br>
  <em><b>Fig 2:</b> PowerShell output showing successful execution of the Mimikatz simulation.</em>
</p>

**The Detection (Blue Team):** I configured a Splunk alert to ingest PowerShell Operational logs and identify the specific signature of this attack.

**Splunk Processing Language (SPL):**

```spl
index=mydfir-project "invoke-mimikatz" EventCode=4104 source="*PowerShell/Operational*"
| stats count min(_time) as first_seen max(_time) as last_seen by user, ComputerName
| sort - count
```

<p align="center">
  <img src="https://github.com/chalithah/SOC-Automation-Lab/blob/6939cd0d111331e5ec5a63aa38b081e2d625339c/assets/images/splunk-search.png" width="800">
  <br>
  <em><b>Fig 3:</b> Verifying that Splunk successfully ingested Mimikatz execution logs.</em>
</p>

**Alert Configuration & Logic:** I configured the alert with specific keywords (`invoke-mimikatz`), source filtering (`PowerShell/Operational`), and a 24-hour throttle. This reduces false positives while ensuring real Mimikatz attacks are detected and reported immediately without flooding the analyst with duplicate tickets.

I set the severity to HIGH because Mimikatz is a critical threat tool used for credential extraction. This ensures the automation pipeline treats it as an urgent incident requiring immediate AI analysis.

<p align="center">
  <img src="https://github.com/chalithah/SOC-Automation-Lab/blob/6939cd0d111331e5ec5a63aa38b081e2d625339c/assets/images/splunk-alert-config.png" width="600">
  <br>
  <em><b>Fig 4:</b> Tuning the alert logic to prevent alert fatigue while maintaining high severity for critical threats.</em>
</p>

---

### 3. Orchestration & Automation (n8n)

I deployed n8n via Docker to orchestrate the incident response workflow. This acts as the "glue" connecting the different security tools.

- **Enrichment:** The workflow extracts IPs and Hashes and queries VirusTotal/AbuseIPDB.
- **AI Analysis:** It pushes the data to an LLM (OpenAI) to generate a human-readable summary and recommended actions.

<p align="center">
  <img src="https://github.com/chalithah/SOC-Automation-Lab/blob/fd8dbdc1d0849a68e5a169234a248d04f534b4a9/assets/images/n8n-workflow.png" width="800">
  <br>
  <em><b>Fig 5:</b> End-to-End SOC automation workflow: Splunk detection → AI analysis → enrichment → IRIS ticket + Slack alert.</em>
</p>

**The Deliverable:** The automation bot posts a structured alert to Slack, allowing the SOC team to see the threat summary, enrichment data, and severity without logging into the SIEM.

<p align="center">
  <img src="https://github.com/chalithah/SOC-Automation-Lab/blob/6939cd0d111331e5ec5a63aa38b081e2d625339c/assets/images/slack-alert.png" width="800">
  <br>
  <em><b>Fig 6:</b> Final alert delivered to the analyst with AI-generated summary and recommendations.</em>
</p>

#### AI Prompt Configuration

The OpenAI node in the n8n workflow uses the following prompt to ensure consistent, high-quality threat analysis:

```
Act as a Tier 1 SOC analyst assistant. When provided with a security alert or incident details (including indicators of compromise, logs, or metadata), perform the following steps:

Summarize the alert – Provide a clear summary of what triggered the alert, which systems/users are affected, and the nature of the activity (e.g., suspicious login, malware detection, lateral movement).

Enrich with threat intelligence – Correlate any IOCs (IP addresses, domains, hashes) with known threat intel sources. For any IP enrichment use the tool named 'AbuseIPDB-Enrichment'. For any File Hash use the tool named 'VirusTotal-Hash' and use the URL: 'https://www.virustotal.com/api/v3/files/{id}' but replace the '{id}' in the url with an actual file hash. Highlight if the indicators are associated with known malware or threat actors.

Assess severity – Based on MITRE ATT&CK mapping, identify tactics/techniques, and provide an initial severity rating (Low, Medium, High, Critical).

Recommend next actions – Suggest investigation steps and potential containment actions.

Format output clearly – Return findings in a structured format (Summary, IOC Enrichment, Severity Assessment, Recommended Actions).

**ALERT DATA:**
Alert: {{ $json.body.search_name }}
Alert Details: {{ JSON.stringify($json.body.result, ['_time', 'user', 'ComputerName', 'src_ip'], 2) }}
File Hash: {{ $json.body.file_hash }}
Source IP: {{ $json.body.src_ip }}

**ENRICHMENT DATA:**
AbuseIPDB Results: {{ JSON.stringify($('AbuseIPDB-Enrichment').item.json) }}
VirusTotal Results: {{ JSON.stringify($('VirusTotal-Hash').item.json) }}
```

This prompt ensures the AI:
- Provides structured, consistent analysis for every alert
- Incorporates threat intelligence from AbuseIPDB and VirusTotal
- Maps threats to the MITRE ATT&CK framework
- Delivers actionable recommendations for SOC analysts

---

### 4. Case Management (DFIR-IRIS)

To move beyond simple alerting, I integrated DFIR-IRIS for formal case tracking.

Configured the n8n workflow to map JSON alert data directly into the IRIS database via API.

This ensures an immutable audit trail is created for every detected incident.

<p align="center">
  <img src="https://github.com/chalithah/SOC-Automation-Lab/blob/6939cd0d111331e5ec5a63aa38b081e2d625339c/assets/images/iris-ticket.png" width="800">
  <br>
  <em><b>Fig 7:</b> Automated ticket creation in IRIS Case Management with IOC enrichment populated.</em>
</p>

---

### 5. Advanced AI Integration (Claude MCP Server)

As an advanced feature, I implemented the Model Context Protocol (MCP) to bridge Claude Desktop with my local Splunk instance. This enables "Chat with your Data" capabilities.

**Infrastructure as Code:** I configured the `claude_desktop_config.json` to allow the LLM to execute Python scripts securely against the Splunk API.

<p align="center">
  <img src="https://github.com/chalithah/SOC-Automation-Lab/blob/dbdadffa1bed41ee8e8a13e8a34f58beb3180cab/assets/images/claude-config-JSON.png" width="500">
  <br>
  <em><b>Fig 8:</b> Configuring the JSON bridge between the LLM and the local Splunk server.</em>
</p>


<p align="center">
  <img src="https://github.com/chalithah/SOC-Automation-Lab/blob/6003a3b3dd7cece0c77e1263bd2527b819581ccd/assets/images/mcp-server-status.png" width="800">
  <br>
  <em><b>Fig 9:</b> Verifying that the local MCP server is running and connected.</em>
</p>

**The AI Analyst:** I can now ask Claude natural language questions like "Show me suspicious activity from the last hour," and the AI generates the SPL, queries the database, and summarizes the results without me writing code.

<p align="center">
  <img src="https://github.com/chalithah/SOC-Automation-Lab/blob/6003a3b3dd7cece0c77e1263bd2527b819581ccd/assets/images/claude-analysis.png" width="800">
  <br>
  <em><b>Fig 10:</b> AI Agent independently querying Splunk and summarizing the Credential Dumping attack.</em>
</p>

---

## Core Technical Capabilities

- **SIEM Administration:** Log parsing, Universal Forwarder configuration, and SPL querying.
- **Detection Engineering:** Tuning alerts to reduce false positives and assigning appropriate risk scores.
- **SOAR Development:** Building API-based workflows and handling JSON data structures.
- **Infrastructure:** Docker container management, Linux CLI administration, and VMware networking.
- **AI Engineering:** Implementing local LLM integrations via Model Context Protocol (MCP).
- **Threat Intelligence:** Automating reputation checks via APIs.
