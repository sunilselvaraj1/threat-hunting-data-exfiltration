
# 🕵️ Threat Hunting Project: Data Exfiltration Attempt by PIP’d Employee

## 📘 Investigation Scenario

**Objective**: Investigate potential data exfiltration activity by an internal employee using Microsoft Defender for Endpoint (MDE).

**Background**:  
An employee named **Sunil**, working in a sensitive department, has recently been placed on a **Performance Improvement Plan (PIP)**. After a verbal outburst, the management suspects he might attempt to **steal sensitive data** before resigning. You have been assigned to investigate activities on his corporate Windows machine (`windows-target-1`) to ensure no suspicious behaviour is taking place.

---

## 🧭 Threat Hunting Steps

### 1️⃣ Preparation

**Goal**: Define a hypothesis based on threat intel and system behaviour.

- Sunil has administrative access and is not restricted in application usage.
- He may try to **compress sensitive files** and upload them to an **external storage service**.
- **Hypothesis**: Sunil is archiving internal data and attempting exfiltration via external cloud storage using custom scripts.

---

### 2️⃣ Data Collection

**Goal**: Identify and collect relevant logs from MDE.

**Tables queried**:
- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceNetworkEvents`

Ensure recent logs are available for `windows-target-1`.

---

### 3️⃣ Data Analysis

**Goal**: Validate hypothesis using data.

- Look for **anomalous behaviour** such as usage of archiving tools or suspicious scripting.
- Identify the **timestamp** of unusual process activity and cross-reference it across other event logs.

---

### 4️⃣ Investigation

**Goal**: Deep dive into findings and map them to MITRE ATT&CK TTPs.

---

### 5️⃣ Response

**Goal**: Contain and escalate if a threat is validated.

- The system was **isolated** upon detection of archiving activity.
- Report submitted to Sunil’s manager, including evidence and analysis.

---

### 6️⃣ Documentation

**Goal**: Record all investigative steps, findings, and queries.

This README is part of that documentation.

---

### 7️⃣ Improvement

**Goal**: Strengthen the security posture.

- Monitor admin access more closely.
- Set alerts on suspicious scripting, archiving tools, and outbound HTTPS to cloud storage.

---

## 🔍 Findings Summary

### Step 1: Detect Archiving Tools

**Query**:
```kusto
let archive_apps = dynamic(["winrar.exe", "7z.exe", "winzip32.exe", "peazip.exe", "Bandizip.exe", "UniExtract.exe", "POWERARC.EXE", "IZArc.exe", "AshampooZIP.exe", "FreeArc.exe"]);
let VMName = "sunil-vm7";
DeviceProcessEvents
| where DeviceName == VMName
| where FileName has_any(archive_apps)
| order by Timestamp desc
```

**Result**:  
`7z.exe` was executed — a known compression tool.  

A suspicious PowerShell script was found associated with this execution.

---

### 🔧 PowerShell Script Behaviour

- **Setup**: Logging with `entropygorilla.log`
- **Data Creation**: Fakes sensitive-looking employee CSV data
- **Tool Installation**: Silently installs `7-Zip` from an external URL
- **Archiving**: Compresses fake CSV into `.zip` using 7-Zip
- **Exfiltration**: Uploads to `sacyberrangedanger.blob.core.windows.net` using Azure Storage API and hardcoded keys
- **Concealment**: Moves files to `C:\ProgramData` for stealth
- **Logging**: Records all operations

---

### Step 2: File Activity Around Compression

**Query**:
```kusto
let specificTime = datetime(2025-07-07T13:14:14.0611598Z);
let VMName = "sunil-vm7";
DeviceFileEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc
```

**Finding**:  
Multiple file creation, modification, and rename events occurred — including `.zip` and `.csv` files matching script activity.

---

### Step 3: Check Network Activity (Exfiltration Attempt)

**Query**:
```kusto
let VMName = "sunil-vm7";
let specificTime = datetime(2025-07-07T13:14:14.0611598Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

**Finding**:  
HTTPS network activity was observed. The destination domain matches **Azure Blob Storage**, indicating an **exfiltration attempt**.

---

## 🧯 Response

- **Immediate action**: Isolated the device.
- **Reported**: Findings communicated to management.
- **Result**: While exfiltration was attempted, no evidence confirmed successful data extraction.

---

## 🧠 MITRE ATT&CK TTPs Identified

| Technique ID | Technique | Description |
|--------------|-----------|-------------|
| **T1059.001** | PowerShell | Used to run the script that performed all actions |
| **T1560.001** | Archive via Utility | Data compressed using 7-Zip |
| **T1048.003** | Exfiltration to Cloud Storage | Azure Blob upload attempted |
| **T1071.001** | Web Protocols | HTTPS used for outbound connection |
| **T1105** | Ingress Tool Transfer | 7-Zip downloaded from internet |
| **T1036.005** | Masquerading | Files saved in `C:\ProgramData` for stealth |
| **T1070.004** | Indicator Removal | Files were relocated for concealment |
| **T1027** | Obfuscated Files | Script silently executed and hidden |
| **T1005** | Data from Local System | CSV created locally before compression |

---

## 📄 Notes

This project is part of a practical threat hunting lab designed to identify data exfiltration attempts by insiders. The hunt was successful in identifying suspicious activities through event correlation and MITRE ATT&CK mapping.

---

## 🧰 Tools Used

- Microsoft Defender for Endpoint (MDE)
- KQL (Kusto Query Language)
- PowerShell (Log analysis + Attack emulation)
- Azure Blob Storage (used in the attack scenario)
- MITRE ATT&CK Framework
