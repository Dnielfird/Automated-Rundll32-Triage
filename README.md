# 🛡️ Automated Rundll32 Triage & Threat Hunting Playbook

## Overview
This repository contains a comprehensive **Threat Hunting Playbook (.docx)** and a custom **Python Automation Script (.py)** designed to detect and triage **Living Off The Land (LOLBin)** abuse involving `rundll32.exe`.

Adversaries frequently use `rundll32.exe` to proxy execution of malicious code, dump credentials, and bypass application whitelisting. This toolset is designed for **SOC Analysts** and **Threat Hunters** to rapidly investigate these threats.

---

## 📄 1. The Threat Hunting Playbook
The included Word document (`Rundll32_Playbook.docx`) serves as a Standard Operating Procedure (SOP) for SOC analysts. It includes:
* **MITRE ATT&CK Mappings:** (e.g., T1218.011: System Binary Proxy Execution).
* **Investigation Workflows:** Step-by-step procedures for validating malicious Rundll32 executions.
* **Environmental Noise:** Known false-positive indicators and benign administrative uses.

---

## 🐍 2. The Python Automation Script
`threat_huntRundll32.py` queries **Elasticsearch** logs, applies a specific **7-Rule Threat Playbook**, filters out known system noise, and generates a structured **Excel Report** separating raw detections from high-confidence malicious activity.

### 🔍 7-Rule Detection Engine
The script validates events against 7 specific attack vectors:
1. **Credential Dumping:** Detects `comsvcs.dll` usage to dump LSASS memory.
2. **Masquerading:** Identifies `rundll32` loading non-DLL extensions (`.txt`, `.jpg`, `.tmp`).
3. **Ordinal Obfuscation:** Detects execution via export numbers (e.g., `#1`) from suspicious paths.
4. **Scripting Abuse:** Flags `javascript:` or `vbscript:` protocol handlers executing code.
5. **Remote Loading:** Detects DLL loads from the Internet (`http`) or Lateral Movement via Hidden Admin Shares (`\\C$`, `\\Admin$`).
6. **Advanced Installers:** Detects silent abuse of `advpack.dll`, `ieframe.dll`, and `FileProtocolHandler`.
7. **Evasion:** Flags NTFS Alternate Data Streams (ADS), `Zipfldr` proxying, and obfuscated GUIDs.

### 🔇 Smart Noise Filtering
The tool automatically drops high-volume False Positives before they reach the analyst, including:
* Windows Network Diagnostics (`ndfapi.dll`)
* Program Compatibility Assistant (`PcaSvc.dll`)
* Edge & Store App Background Tasks (`EdgeHtml.dll`)
* Startup Scanners (`Startupscan.dll`)
* Safe COM/DCOM Server Hosting (`svchost` spawning `shell32`)

---

## 📊 3. Script Execution & Output Guide
Once the script finishes querying Elasticsearch, it relies on the `openpyxl` library to generate a highly structured Excel (`.xlsx`) report. 

**How to read the Excel Report:**
For every threat rule (Rules 1 through 7), the script generates **two** dedicated sheets:
* **`[RULE_NAME]_Detections` Sheet:** Contains all raw log events that triggered the baseline rule.
* **`[RULE_NAME]_Analysis` Sheet:** Contains events the engine has flagged as a **True Positive (TP)** based on parent-process relationships and secondary indicators. 
  * *UI Feature:* High-confidence malicious rows are automatically highlighted in **RED** and include an `ANALYST_CAUTION_CHECKLIST` column explaining exactly *why* it bypassed the safe filters (e.g., *"LSASS Dump Detected. CAUTION: Verify Parent is NOT SCCM/Tanium"*).

---

## 🛠️ Installation & Setup

### 1. Prerequisites
* Python 3.6+
* Network access to your Elasticsearch instance.

### 2. Install Dependencies
Run the following command to install the required Python libraries:
```bash
pip install elasticsearch openpyxl python-dotenv python-dateutil
```

### 3. Configuration
* Create a file named .env in the project root directory and add your Elasticsearch credentials:

```bash
# .env file configuration
ES_URL="https://your-elastic-instance:9200"
ES_API_KEY="your_api_key_here"
ES_INDEX="logs-endpoint-*"  # Change to match your index pattern
VERIFY_CERTS="false"        # Set to 'true' if using valid SSL certificates
```

## 💻 How to Run (Prompting the Code)
The script uses the -t flag to specify the Time Range and the -o flag for the Output Filename.

###🔹 Scenario 1: Specific Date Range (Broad Hunt)
Use this to scan entire days (Midnight to Midnight). Note: You must use quotation marks "" if your date contains spaces.

```bash
python threat_huntRundll32.py -t "20-01-2026 to 22-01-2026" -o weekend_hunt.xlsx
```
Start: Jan 20, 2026 at 00:00:00 | End: Jan 22, 2026 at 23:59:59

### 🔹 Scenario 2: Specific Time Window (Precision Hunt)
Use this when investigating a specific incident timestamp. The tool is smart enough to parse hours and minutes.

```bash
python threat_huntRundll32.py -t "20-01-2026 14:30 to 20-01-2026 16:45" -o incident_report.xlsx
```
Start: Jan 20, 2026 at 2:30 PM | End: Jan 20, 2026 at 4:45 PM

### 🔹 Scenario 3: Relative Time (Quick Check)
Use this for daily checks or recent alerts.

```bash
python threat_huntRundll32.py -t 24h -o daily_report.xlsx   # Last 24 Hours
python threat_huntRundll32.py -t 7d -o weekly_report.xlsx   # Last 7 Days
python threat_huntRundll32.py -t 30m -o recent_alert.xlsx   # Last 30 Minutes
```

### 🔹 Scenario 4: Standard ISO Format
You can also use standard ISO database timestamps if you prefer.

```bash
python threat_huntRundll32.py -t "2026-01-20T10:00:00 to 2026-01-20T11:00:00" -o results.xlsx
```
