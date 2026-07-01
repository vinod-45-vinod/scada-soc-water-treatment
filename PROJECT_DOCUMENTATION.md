# SOC-MINI: SCADA/ICS Security Operations Center

## Integrating SCADA Security SOC for Municipal Water Treatment Plant

---

## 1. PROJECT OVERVIEW

**SOC-MINI** is a fully functional Security Operations Center (SOC) built for monitoring and protecting SCADA/ICS (Supervisory Control and Data Acquisition / Industrial Control Systems) environments. The project simulates a **Municipal Water Treatment Plant** with real-time event generation, log enrichment, threat detection, threat hunting, and integration with enterprise security tools.

### Key Objectives
- Real-time security monitoring of SCADA/ICS systems
- Detection of cyber attacks targeting industrial control systems
- Integration with **Wazuh SIEM** for centralized alert management
- Integration with **MISP** (Malware Information Sharing Platform) for threat intelligence
- Proactive **Threat Hunting** using formal hypotheses
- **MITRE ATT&CK for ICS** framework mapping

---

## 2. SYSTEM ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────┐
│                    SOC-MINI Architecture                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌───────────────┐    ┌─────────────────┐  │
│  │   SCADA       │───▶│  Log Enricher  │───▶│   Wazuh SIEM    │  │
│  │  Simulator    │    │  (CTI, IoC,    │    │   (Docker)      │  │
│  │  (Node.js)    │    │   IoA, MITRE)  │    │   Port: 514     │  │
│  └──────────────┘    └───────────────┘    └─────────────────┘  │
│         │                    │                      │           │
│         │                    │                      │           │
│         ▼                    ▼                      ▼           │
│  ┌──────────────┐    ┌───────────────┐    ┌─────────────────┐  │
│  │  WebSocket    │    │  Threat       │    │  Wazuh Agent    │  │
│  │  Dashboard    │    │  Hunter       │    │  (Windows)      │  │
│  │  Port: 3000   │    │  (6 Hunts)    │    │  Agent ID: 003  │  │
│  └──────────────┘    └───────────────┘    └─────────────────┘  │
│                              │                                  │
│                              ▼                                  │
│                      ┌───────────────┐                          │
│                      │     MISP      │                          │
│                      │  (Docker)     │                          │
│                      │  Port: 8443   │                          │
│                      └───────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Technology | Port | Purpose |
|-----------|-----------|------|---------|
| **Backend Server** | Node.js (Express + WebSocket) | 3000 | Event processing, API, real-time dashboard |
| **SCADA Simulator** | Node.js | — | Generates realistic SCADA events & attack scenarios |
| **Log Enricher** | Node.js | — | CTI, IoC, IoA, MITRE ATT&CK enrichment |
| **Wazuh Manager** | Docker Container | 514 (UDP), 55000 (API) | SIEM — centralized log analysis & alerting |
| **Wazuh Agent** | Windows Service | — | Forwards local SCADA logs to Wazuh Manager |
| **MISP** | Docker Container | 8443 (HTTPS) | Threat Intelligence Platform — IOC sharing |
| **Threat Hunter** | Node.js | — | Proactive threat hunting with 3 formal hypotheses |
| **Frontend Dashboard** | HTML/CSS/JS | 3000 | Real-time SOC monitoring interface |

---

## 3. SCADA PLANT CONFIGURATION

### Plant: Municipal Water Treatment Plant — Unit 7

### Sensors Monitored

| Sensor | Normal Range | Critical Low | Critical High | Unit |
|--------|-------------|--------------|---------------|------|
| **pH** | 6.5 – 8.5 | 5.0 | 10.0 | pH |
| **Chlorine** | 0.2 – 4.0 | 0.0 | 6.0 | mg/L |
| **Turbidity** | 0.0 – 1.0 | 0.0 | 5.0 | NTU |
| **Flow Rate** | 100 – 500 | 50 | 800 | GPM |
| **Pressure** | 30 – 80 | 15 | 120 | PSI |
| **Temperature** | 15 – 30 | 5 | 45 | °C |

### PLC Controllers

| PLC ID | Name | Zone |
|--------|------|------|
| **PLC-001** | Chemical Dosing Controller | CHEMICAL |
| **PLC-002** | Filtration System Controller | FILTRATION |
| **PLC-003** | Pump Station Controller | PUMPING |
| **PLC-004** | Distribution Valve Controller | DISTRIBUTION |

### HMI Stations

| Station ID | Name | Operator |
|-----------|------|----------|
| HMI-01 | Main Control Room | operator1 |
| HMI-02 | Remote Monitoring | operator2 |
| HMI-03 | Engineering Workstation | engineer1 |

---

## 4. EVENT TYPES

The simulator generates the following event types:

| Event Type | Description | Severity | Context |
|-----------|-------------|----------|---------|
| `SENSOR_READING` | Normal sensor data within range | LOW | Routine monitoring |
| `SENSOR_ANOMALY` | Sensor value outside normal range | HIGH/CRITICAL | Possible manipulation or equipment failure |
| `PLC_COMMAND` | Command sent to PLC controller | LOW (Authorized) / CRITICAL (Unauthorized) | Process control |
| `LOGIN_ATTEMPT` | Authentication event on HMI | MEDIUM (Failed) / LOW (Success) | Access control |
| `MALWARE_DETECTED` | ICS malware found on system | CRITICAL | Triton, Industroyer, Stuxnet signatures |
| `LATERAL_MOVEMENT` | IT to OT network crossing | HIGH | Network boundary violation |
| `SYSTEM_HEALTH` | Infrastructure health check | LOW | Routine |

---

## 5. LOG ENRICHMENT PIPELINE

Each raw SCADA event passes through **6 enrichment layers** before being sent to Wazuh:

```
Raw Event → CTI Enrichment → IoC Enrichment → IoA Enrichment
         → MITRE Mapping → Attack Stage → Risk Score Calculation
         → Formatted Syslog → Wazuh (UDP + File)
```

### 5.1 CTI (Cyber Threat Intelligence) Enrichment

Checks source IPs against threat intelligence feeds (hardcoded + MISP):

| Tag | Meaning | Severity Impact |
|-----|---------|-----------------|
| `THREAT_INTEL_MATCH` | IP matches known malicious indicator from CTI/MISP | → CRITICAL |
| `SUSPICIOUS_IP` | IP flagged as suspicious but not confirmed | → HIGH |
| `UNKNOWN_EXTERNAL` | External IP not in known-good list | → MEDIUM |
| `CLEAN` | Internal/known-good IP | No change |

**Malicious IPs (Simulated CTI Feed):**
- `198.51.100.23`, `203.0.113.42`, `192.0.2.99`, `198.51.100.77`, `203.0.113.15`

### 5.2 IoC (Indicators of Compromise) Enrichment

| IoC Type | Trigger | Description |
|----------|---------|-------------|
| `MALICIOUS_IP` | Source IP in threat intel list | Known attacker infrastructure |
| `FAILED_AUTH` | Failed login attempt | Potential credential guessing |
| `ANOMALOUS_SENSOR_DATA` | Sensor out of range | Possible data manipulation |
| `MALWARE_SIGNATURE` | Malware detection event | Known ICS malware signature |
| `UNAUTHORIZED_ACCESS` | Unauthorized PLC command | Credential abuse |
| `NETWORK_ANOMALY` | Lateral movement detected | Network boundary violation |

### 5.3 IoA (Indicators of Attack) Enrichment

| IoA Type | Trigger | Description |
|----------|---------|-------------|
| `BRUTE_FORCE_BEHAVIOR` | 3+ failed logins from same IP in 5 minutes | Active brute force attack pattern |
| `UNAUTHORIZED_PLC_EXECUTION` | Unauthorized PLC command | Attacker controlling industrial process |
| `SENSOR_MANIPULATION` | Sensor anomaly events | Attacker modifying sensor readings |
| `MALWARE_EXECUTION` | Malware detected on ICS | Active malware running on SCADA |
| `IT_OT_BOUNDARY_CROSSING` | Lateral movement | Attacker moving from IT to OT |

### 5.4 Risk Score Calculation (0–100)

```
Risk Score = Severity Weight + CTI Bonus + IoC Bonus + IoA Bonus

Severity Weights:  LOW=10, MEDIUM=30, HIGH=60, CRITICAL=90
CTI Bonus:         THREAT_INTEL_MATCH = +10
IoC Bonus:         Any IoC detected = +5
IoA Bonus:         Any IoA detected = +5
```

---

## 6. WAZUH CUSTOM DETECTION RULES

All custom rules use IDs in range **100100–100199** and are deployed to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager.

### 6.1 Base SCADA Rules (100100–100109)

| Rule ID | Level | Description | Trigger |
|---------|-------|-------------|---------|
| **100100** | 6 | SCADA SOC event received | `match: SCADA_SOC:` — catches all SCADA logs. Level 6 to override built-in rule 2501 (level 5) |
| **100101** | 2 | Normal sensor reading | `event_type=SENSOR_READING` |
| **100102** | 2 | System health check | `event_type=SYSTEM_HEALTH` |

### 6.2 Login Detection Rules (100110–100119)

| Rule ID | Level | MITRE | Description | Trigger |
|---------|-------|-------|-------------|---------|
| **100110** | 3 | T1078 | Successful SCADA login | `event_type=LOGIN_ATTEMPT` + `status=SUCCESS` |
| **100111** | 6 | T1110 | Failed SCADA login (brute force) | `event_type=LOGIN_ATTEMPT` + `status=FAILED` |
| **100112** | 12 | T1110 | **BRUTE FORCE ATTACK** — 5 failed logins from same IP in 60 seconds | `if_matched_sid: 100111` + `frequency=5` + `timeframe=60` + `same_source_ip` |

### 6.3 PLC Command Rules (100120–100129)

| Rule ID | Level | MITRE | Description | Trigger |
|---------|-------|-------|-------------|---------|
| **100120** | 3 | — | Authorized PLC command | `event_type=PLC_COMMAND` + `status=AUTHORIZED` |
| **100121** | 14 | T0859 | **Unauthorized PLC command execution** | `event_type=PLC_COMMAND` + `status=UNAUTHORIZED` |
| **100122** | 13 | — | Unauthorized PLC setpoint modification | `plc_command=MODIFY_SETPOINT` (chains from 100121) |
| **100123** | 15 | T0829 | **EMERGENCY: PLC safety logic modification** | `plc_command=MODIFY_SAFETY_LOGIC` (chains from 100121) |

### 6.4 Sensor Anomaly Rules (100130–100139)

| Rule ID | Level | Description | Trigger |
|---------|-------|-------------|---------|
| **100130** | 10 | Sensor anomaly detected | `event_type=SENSOR_ANOMALY` |
| **100131** | 13 | Critical sensor — public health risk | `sensor_status=CRITICAL` (chains from 100130) |
| **100132** | 12 | pH sensor anomaly — chemical attack | `sensor_type=pH` (chains from 100130) |
| **100133** | 12 | Chlorine anomaly — disinfection compromised | `sensor_type=chlorine` (chains from 100130) |
| **100134** | 11 | Turbidity anomaly — water clarity | `sensor_type=turbidity` (chains from 100130) |

### 6.5 Malware Detection Rules (100140–100149)

| Rule ID | Level | MITRE | Description | Trigger |
|---------|-------|-------|-------------|---------|
| **100140** | 14 | T1070 | Malware detected on SCADA | `event_type=MALWARE_DETECTED` |
| **100141** | 15 | T0829 | **TRITON/TRISIS** malware — SIS attack | `Triton` (chains from 100140) |
| **100142** | 15 | — | **INDUSTROYER** malware | `Industroyer` (chains from 100140) |
| **100143** | 15 | — | **STUXNET-variant** malware | `Stuxnet` (chains from 100140) |

### 6.6 IoC Detection Rules (100150–100159)

| Rule ID | Level | Description | Trigger |
|---------|-------|-------------|---------|
| **100150** | 10 | Malicious IP indicator | `ioc_type=MALICIOUS_IP` |
| **100151** | 9 | Anomalous sensor data indicator | `ioc_type=ANOMALOUS_SENSOR_DATA` |
| **100152** | 12 | Malware signature indicator | `ioc_type=MALWARE_SIGNATURE` |
| **100153** | 11 | Unauthorized access indicator | `ioc_type=UNAUTHORIZED_ACCESS` |
| **100154** | 10 | Network anomaly indicator | `ioc_type=NETWORK_ANOMALY` |

### 6.7 IoA Detection Rules (100160–100169)

| Rule ID | Level | Description | Trigger |
|---------|-------|-------------|---------|
| **100160** | 12 | Brute force behavior pattern | `ioa_type=BRUTE_FORCE_BEHAVIOR` |
| **100161** | 14 | Unauthorized PLC execution pattern | `ioa_type=UNAUTHORIZED_PLC_EXECUTION` |
| **100162** | 11 | Sensor data manipulation behavior | `ioa_type=SENSOR_MANIPULATION` |
| **100163** | 13 | Malware execution behavior | `ioa_type=MALWARE_EXECUTION` |
| **100164** | 11 | IT/OT boundary crossing | `ioa_type=IT_OT_BOUNDARY_CROSSING` |

### 6.8 MITRE ATT&CK Mapping Rules (100170–100179)

| Rule ID | Level | MITRE ID | Technique | Tactic |
|---------|-------|----------|-----------|--------|
| **100170** | 6 | T1078 | Valid Accounts | Initial Access |
| **100171** | 10 | T1110 | Brute Force | Credential Access |
| **100172** | 8 | T0859 | Valid Accounts (ICS) | Execution |
| **100173** | 13 | T0855 | Unauthorized Command Message | Impair Process Control |
| **100174** | 10 | T0832 | Manipulation of View | Evasion |
| **100175** | 14 | T0829 | Modify Control Logic | Impact |
| **100176** | 11 | T0866 | Exploitation of Remote Services | Lateral Movement |

### 6.9 CTI Detection Rules (100180–100189) — Highest Priority

| Rule ID | Level | MITRE | Description | Chain |
|---------|-------|-------|-------------|-------|
| **100180** | 14 | — | Threat Intel Match — malicious IP detected | `threat_intel_tag=THREAT_INTEL_MATCH` |
| **100181** | 15 | — | CTI Alert: Malicious IP attempting SCADA login | chains from 100180 + `LOGIN_ATTEMPT` |
| **100182** | 15 | — | CTI Alert: Malicious IP sending PLC commands | chains from 100180 + `PLC_COMMAND` |
| **100183** | 15 | — | CTI Alert: Malware from known threat actor | chains from 100180 + `MALWARE_DETECTED` |
| **100184** | 15 | T1110 | **BRUTE FORCE from known threat actor** | chains from 100181 + `BRUTE_FORCE_BEHAVIOR` |
| **100185** | 8 | — | Suspicious IP flagged | `threat_intel_tag=SUSPICIOUS_IP` |
| **100186** | 15 | T1110 | CTI: Failed login from malicious IP | chains from 100181 + `status=FAILED` |

### 6.10 Lateral Movement Rules (100190–100199)

| Rule ID | Level | MITRE | Description | Trigger |
|---------|-------|-------|-------------|---------|
| **100190** | 12 | T1021 | Lateral movement: IT to OT crossing | `event_type=LATERAL_MOVEMENT` |
| **100191** | 15 | T1021 | Known threat actor performing lateral movement | chains from 100190 + `THREAT_INTEL_MATCH` |

### 6.11 Severity-Based Rules (100195–100199)

| Rule ID | Level | Description |
|---------|-------|-------------|
| **100195** | 13 | Critical severity SCADA event |
| **100196** | 10 | High severity SCADA event |

---

## 7. MITRE ATT&CK MAPPING TABLE

| Attack Step | MITRE Tactic | Technique ID | Technique Name | Description |
|------------|-------------|-------------|----------------|-------------|
| Initial Access | Initial Access | **T1078** | Valid Accounts | Attacker uses stolen or brute-forced credentials to access SCADA |
| Execution | Execution | **T0859** | Command Execution (ICS) | Attacker sends unauthorized commands to PLC devices |
| Persistence | Persistence | **T1136** | Create Account | Attacker creates new user account to maintain access |
| Defense Evasion | Defense Evasion | **T1070** | Indicator Removal | Attacker deletes or modifies logs to hide activity |
| Lateral Movement | Lateral Movement | **T1021** | Remote Services | Attacker moves from IT network to OT network systems |
| Impact | Impact | **T0829** | Modify Control Logic | Attacker changes PLC logic affecting chemical dosing |

### Additional ICS-Specific MITRE Techniques Used

| Technique ID | Name | Tactic | Where Used |
|-------------|------|--------|------------|
| **T1110** | Brute Force | Credential Access | Brute force login detection (Rule 100112) |
| **T0855** | Unauthorized Command Message | Impair Process Control | Unauthorized PLC commands (Rule 100173) |
| **T0832** | Manipulation of View | Evasion | Sensor data tampering (Rule 100174) |
| **T0866** | Exploitation of Remote Services | Lateral Movement | IT→OT lateral movement (Rule 100176) |

---

## 8. THREAT HUNTING HYPOTHESES

### Hypothesis 1 — Unauthorized Modbus/TCP Communication to PLCs (HUNT-H1)

| Field | Details |
|-------|---------|
| **Hypothesis** | If Modbus/TCP communication is observed from unknown IP addresses to PLC controllers, it may indicate unauthorized command injection. |
| **Data Sources** | Firewall Logs, Network Device Logs, PLC Command Logs |
| **Why Suspicious** | Only authorized SCADA systems should communicate with PLCs. Any external communication is abnormal. |
| **Expected Outcome** | Identify rogue devices or attackers attempting to manipulate industrial processes |
| **Detection Logic** | Looks for `PLC_COMMAND` events from non-internal IPs, `status=UNAUTHORIZED`, or dangerous commands (`MODIFY_SETPOINT`, `MODIFY_SAFETY_LOGIC`, `INJECT_PAYLOAD`, `OVERRIDE_PRESSURE`) |
| **MITRE Mapping** | T0855 — Unauthorized Command Message / T0829 — Modify Control Logic |

### Hypothesis 2 — Brute-Force Attack Pattern (HUNT-H2)

| Field | Details |
|-------|---------|
| **Hypothesis** | If multiple failed login attempts followed by a successful login occur on SCADA systems, it may indicate a brute-force attack. |
| **Data Sources** | Windows Security Logs, VPN Authentication Logs, SCADA HMI Access Logs |
| **Why Suspicious** | This pattern is commonly used by attackers to guess passwords and gain unauthorized access. |
| **Expected Outcome** | Detect compromised operator accounts and prevent unauthorized access |
| **Detection Logic** | Groups `LOGIN_ATTEMPT` events by source IP. If 3+ `FAILED` followed by a `SUCCESS` from same IP → `BRUTE_FORCE_WITH_CREDENTIAL_COMPROMISE` (CRITICAL). If only 3+ `FAILED` → `BRUTE_FORCE_ATTACK_IN_PROGRESS` (HIGH). |
| **MITRE Mapping** | T1110 — Brute Force → T1078 — Valid Accounts |

### Hypothesis 3 — Malware on Operator Workstation (HUNT-H3)

| Field | Details |
|-------|---------|
| **Hypothesis** | If malware is detected on an operator workstation connected to the SCADA network, it may indicate an attempt to control PLC systems. |
| **Data Sources** | EDR Logs, Windows Event Logs, Antivirus/Anti-malware Logs |
| **Why Suspicious** | Operator workstations have direct access to critical PLC systems and are high-value targets. ICS-specific malware (Triton, Industroyer, Stuxnet) directly targets safety and control systems. |
| **Expected Outcome** | Identify infected systems and isolate them before damage occurs |
| **Detection Logic** | Detects `MALWARE_DETECTED` events. Correlates malware source IPs with subsequent `PLC_COMMAND` events from same IPs. If found → `MALWARE_DRIVEN_PLC_MANIPULATION` (CRITICAL). |
| **MITRE Mapping** | T0829 — Modify Control Logic / T0831 — Manipulation of Control |

### Supporting Hunts

| Hunt ID | Name | Description |
|---------|------|-------------|
| HUNT-S1 | Sensor Anomaly Detection | Detects critically out-of-range sensor readings |
| HUNT-S2 | IT to OT Lateral Movement | Detects unauthorized network boundary crossings |
| HUNT-S3 | Threat Intelligence Correlation | Correlates events with known malicious IPs |

---

## 9. ATTACK SCENARIOS (SIMULATION)

The simulator supports 5 attack scenarios:

### Scenario 1: Brute Force Login Attack
- **ID:** `brute_force`
- **Description:** Multiple failed login attempts from malicious IP
- **Kill Chain Stage:** Initial Access
- **Events Generated:** 5 `LOGIN_ATTEMPT` with `status=FAILED` from random malicious IPs

### Scenario 2: Sensor Data Manipulation
- **ID:** `sensor_manipulation`
- **Description:** Attacker modifies pH and chlorine sensor readings
- **Kill Chain Stages:** Execution → Impact
- **Events Generated:** `SENSOR_ANOMALY` with critically out-of-range values

### Scenario 3: PLC Malware Injection
- **ID:** `malware_injection`
- **Description:** Malware deployed to modify PLC logic
- **Kill Chain Stages:** Persistence → Impact
- **Events Generated:** `MALWARE_DETECTED` with ICS malware names (Triton, Industroyer, Stuxnet, BlackEnergy, HavexRAT)

### Scenario 4: IT to OT Lateral Movement
- **ID:** `lateral_movement`
- **Description:** Attacker moves from IT network into OT/SCADA network
- **Kill Chain Stages:** Lateral Movement → Execution
- **Events Generated:** `LATERAL_MOVEMENT` with source and destination IPs

### Scenario 5: Full Attack Chain (Kill Chain)
- **ID:** `full_attack_chain`
- **Description:** Complete attack lifecycle with 10 sequential steps
- **Kill Chain:** Reconnaissance → Initial Access → Execution → Persistence → Impact

| Step | Event Type | Description |
|------|-----------|-------------|
| 1 | LOGIN_ATTEMPT (FAILED) | Port scan / reconnaissance from external IP |
| 2 | LOGIN_ATTEMPT (FAILED) | Brute force on SCADA HMI |
| 3 | LOGIN_ATTEMPT (FAILED) | Continued brute force with operator credentials |
| 4 | LOGIN_ATTEMPT (SUCCESS) | Successful login with compromised credentials |
| 5 | LATERAL_MOVEMENT | IT DMZ to OT SCADA network segment |
| 6 | PLC_COMMAND (UNAUTHORIZED) | Unauthorized command to Chemical Dosing PLC |
| 7 | SENSOR_ANOMALY (CRITICAL) | pH sensor reading 12.5 — chemical dosing overridden |
| 8 | MALWARE_DETECTED | Triton malware on PLC-001 — modifying safety logic |
| 9 | SENSOR_ANOMALY (CRITICAL) | Chlorine at 0.0 mg/L — water treatment compromised |
| 10 | PLC_COMMAND (UNAUTHORIZED) | Pressure override on Pump Station PLC |

---

## 10. MISP INTEGRATION

### Connection Details

| Setting | Value |
|---------|-------|
| URL | `https://localhost:8443` |
| Protocol | HTTPS (self-signed certificate) |
| API Authentication | API Key (set via `MISP_API_KEY` environment variable) |
| Sync Interval | Every 60 seconds |
| Push Alerts | Critical SCADA alerts pushed back to MISP |

### Features

| Feature | Description |
|---------|-------------|
| **Indicator Sync** | Fetches IPs, domains, hashes, URLs from MISP every 60s |
| **Event Enrichment** | MISP IOCs merged with hardcoded threat intel for SCADA event enrichment |
| **Alert Push-back** | Critical SCADA alerts automatically create MISP events |
| **IOC Search** | Search any indicator against MISP database via API |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/misp/status` | GET | MISP connection status and sync stats |
| `/api/misp/sync` | POST | Force sync indicators from MISP |
| `/api/misp/config` | POST | Update MISP URL and API key at runtime |
| `/api/misp/search/:indicator` | GET | Search an indicator in MISP |
| `/api/misp/events` | GET | Fetch recent MISP events |

---

## 11. WAZUH AGENT CONFIGURATION

### Agent Details

| Setting | Value |
|---------|-------|
| Agent Name | `vinod` |
| Agent ID | `003` |
| Manager Address | `127.0.0.1` |
| Protocol | TCP, Port 1514 |
| Crypto | AES |
| Log Format | Syslog |

### Monitored Log File

```xml
<localfile>
  <location>C:\Users\Vinod G R\Desktop\soc-mini\logs\scada-events.log</location>
  <log_format>syslog</log_format>
</localfile>
```

### Log Format (Syslog)

Each log line written to the file follows this format:
```
SCADA_SOC: event_type=LOGIN_ATTEMPT "Failed login attempt" source_ip=198.51.100.23
destination_ip=10.0.1.10 username=admin status=FAILED ioc_type=FAILED_AUTH+MALICIOUS_IP
ioa_type=BRUTE_FORCE_BEHAVIOR attack_stage=Initial Access mitre_id=T1110
mitre_technique=Brute Force threat_severity=CRITICAL
threat_intel_tag=THREAT_INTEL_MATCH risk_score=100
```

---

## 12. RULE CHAINING LOGIC

Wazuh evaluates rules in chains. Only the **highest-level match** generates an alert per log event.

### Example Chain: Brute Force from CTI-Flagged IP

```
Log: SCADA_SOC: event_type=LOGIN_ATTEMPT status=FAILED 
     ioa_type=BRUTE_FORCE_BEHAVIOR threat_intel_tag=THREAT_INTEL_MATCH

Chain 1: 100100 (L6) → 100111 (L6) → detected as base
Chain 2: 100100 (L6) → 100180 (L14) → 100181 (L15) → 100186 (L15)
                                                  └→ 100184 (L15) ← WINNER

Result: Rule 100184 fires — "BRUTE FORCE ATTACK from known threat actor IP"
```

### Why Rule 100100 is Level 6

Built-in Wazuh rule **2501** (level 5) matches generic syslog authentication failures. Since Wazuh picks the **highest level** match, rule 100100 must be level 6+ to win over 2501 and allow our custom rule chain to fire.

---

## 13. PROJECT FILE STRUCTURE

```
soc-mini/
├── backend/
│   ├── server.js          # Main Express + WebSocket server
│   ├── config.js          # All configuration (SCADA, Wazuh, MISP, MITRE)
│   ├── simulator.js       # SCADA event and attack scenario generator
│   ├── enricher.js        # Log enrichment engine (CTI, IoC, IoA, MITRE)
│   ├── wazuh-sender.js    # Sends logs to Wazuh via UDP syslog + file
│   ├── threat-hunter.js   # Proactive threat hunting (3 hypotheses + 3 supporting)
│   └── misp-client.js     # MISP API client for threat intelligence
├── frontend/
│   ├── index.html         # SOC Dashboard HTML
│   ├── app.js             # Dashboard logic (WebSocket, charts, hunt display)
│   └── styles.css         # Dark-theme SOC dashboard styling
├── wazuh-rules/
│   ├── scada_rules.xml    # Custom Wazuh detection rules (100100–100199)
│   ├── ossec_agent.conf   # Wazuh Agent configuration
│   └── test_log.sh        # Script to test rules via wazuh-logtest
├── logs/
│   ├── scada-events.log   # SCADA log file monitored by Wazuh Agent
│   └── soc-alerts.log     # Local alert log
├── package.json           # Node.js dependencies
└── PROJECT_DOCUMENTATION.md  # This file
```

---

## 14. HOW TO RUN

### Prerequisites
- Node.js v18+
- Docker Desktop (for Wazuh Manager and MISP containers)
- Wazuh Agent installed on Windows

### Step 1: Install Dependencies
```bash
cd soc-mini
npm install
```

### Step 2: Deploy Wazuh Rules
```bash
docker cp wazuh-rules/scada_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

### Step 3: Start the SOC Server
```powershell
# Without MISP:
node backend/server.js

# With MISP integration:
$env:MISP_API_KEY='your_api_key_here'
node backend/server.js
```

### Step 4: Restart Wazuh Agent
```powershell
# In Admin PowerShell:
Restart-Service WazuhSvc -Force
```

### Step 5: Access Dashboard
- **SOC Dashboard:** http://localhost:3000
- **Wazuh Dashboard:** https://localhost (Docker)
- **MISP Dashboard:** https://localhost:8443

---

## 15. API REFERENCE

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/simulation/start` | POST | Start normal SCADA simulation |
| `/api/simulation/stop` | POST | Stop normal simulation |
| `/api/scenarios` | GET | List available attack scenarios |
| `/api/attack/start` | POST | Launch attack scenario (`{ "scenario": "brute_force" }`) |
| `/api/attack/stop` | POST | Stop attack scenario |
| `/api/events` | GET | Get recent events (query: `?severity=CRITICAL&limit=50`) |
| `/api/events/:id` | GET | Get specific event by ID |
| `/api/hunt` | GET | Run all threat hunts |
| `/api/hunt/timeline` | GET | Get investigation timeline |
| `/api/metrics` | GET | Get SOC metrics summary |
| `/api/wazuh/status` | GET | Wazuh connection status |
| `/api/wazuh/config` | POST | Update Wazuh target |
| `/api/misp/status` | GET | MISP connection status |
| `/api/misp/sync` | POST | Force sync MISP indicators |
| `/api/misp/search/:indicator` | GET | Search indicator in MISP |
| `/api/misp/events` | GET | Get recent MISP events |
| `/api/inject` | POST | Manually inject a custom event |
| `/api/reset` | POST | Reset all state and counters |
| `/api/config` | GET | Get system configuration |

---

## 16. PHASE 4 — SOAR (Security Orchestration, Automation & Response)

### 16.1 SOAR Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SOAR INCIDENT RESPONSE PIPELINE                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────┐   ┌──────────────┐   ┌─────────────┐   ┌─────────────┐  │
│  │  Alert    │──▶│  VirusTotal  │──▶│   MISP      │──▶│  Decision   │  │
│  │  Trigger  │   │  IP Lookup   │   │  IOC Search │   │   Logic     │  │
│  └──────────┘   └──────────────┘   └─────────────┘   └──────┬──────┘  │
│       ▲                                                      │         │
│       │                                                      ▼         │
│  ┌──────────┐   ┌──────────────┐   ┌─────────────┐   ┌─────────────┐  │
│  │  Shuffle  │◀──│  Incident    │◀──│  Auto       │◀──│ CRITICAL /  │  │
│  │  SOAR     │   │  Report     │   │  Response   │   │ HIGH / MED  │  │
│  │  (Cloud)  │   │  Generator  │   │  Actions    │   │ Classifier  │  │
│  └──────────┘   └──────────────┘   └──────┬──────┘   └─────────────┘  │
│                                           │                            │
│                                           ▼                            │
│                                    ┌─────────────┐                     │
│                                    │   Human     │                     │
│                                    │  Approval   │                     │
│                                    │  (CRITICAL) │                     │
│                                    └─────────────┘                     │
└─────────────────────────────────────────────────────────────────────────┘
```

### 16.2 SOAR Engine — 6-Step Pipeline

| Step | Component | Description |
|------|-----------|-------------|
| **Step 1** | Alert Trigger | Filters incoming events — only triggers for `PLC_COMMAND`, `MALWARE_DETECTED`, `LOGIN_ATTEMPT`, `LATERAL_MOVEMENT`, CTI match, brute force patterns |
| **Step 2** | Automated Enrichment | Queries **VirusTotal** (IP reputation), **MISP** (IOC search), and internal CTI database |
| **Step 3** | Decision Logic | Classifies incident severity: **CRITICAL**, **HIGH**, or **MEDIUM** based on enrichment results |
| **Step 4** | Automated Response | Executes: Block IP → Terminate VPN → Create Ticket → Send Email+SMS notifications |
| **Step 5** | Human Approval | For **CRITICAL** incidents: queues 3 actions requiring analyst approval before execution |
| **Step 6** | Report Generation | Generates comprehensive JSON incident report with timeline, enrichment results, and recommendations |

### 16.3 Incident Classification Matrix

| Classification | Severity | Trigger Conditions |
|---------------|----------|-------------------|
| `PLC_COMMAND_INJECTION_APT` | **CRITICAL** | CTI match + external IP + PLC_COMMAND |
| `ICS_MALWARE_DETECTED` | **CRITICAL** | MALWARE_DETECTED event (Triton, Industroyer, Stuxnet) |
| `BRUTE_FORCE_FROM_KNOWN_THREAT_ACTOR` | **CRITICAL** | CTI match + brute force behavior |
| `MALICIOUS_IP_PLC_ACCESS` | **CRITICAL** | VirusTotal malicious + PLC_COMMAND |
| `THREAT_INTEL_MATCH_ACTIVITY` | **HIGH** | CTI match (any event type) |
| `BRUTE_FORCE_ATTACK` | **HIGH** | Brute force without CTI match |
| `IT_OT_LATERAL_MOVEMENT` | **HIGH** | Lateral movement event |
| `UNAUTHORIZED_PLC_COMMAND` | **HIGH** | Unauthorized PLC command |
| `GENERAL_ALERT` | **MEDIUM** | Other triggered events |

### 16.4 Automated Response Actions

| Action | Severity Required | Description |
|--------|------------------|-------------|
| `LOG_COLLECTION` | All | Evidence logs collected for source IP |
| `BLOCK_IP` | HIGH, CRITICAL | Firewall rule: DENY ALL from IP to OT_NETWORK (10.0.1.0/24) |
| `TERMINATE_VPN` | HIGH, CRITICAL | VPN session terminated, session token revoked |
| `CREATE_TICKET` | HIGH, CRITICAL | Incident ticket created with priority, assignee, and classification |
| `SEND_NOTIFICATIONS` | HIGH, CRITICAL | Email + SMS to SOC team, Plant Manager, and CISO |
| `HUMAN_APPROVAL_REQUIRED` | CRITICAL only | Queues 3 critical actions for analyst approval |
| `MISP_UPDATED` | CRITICAL only | IOC pushed to MISP threat intelligence platform |

### 16.5 Human-in-the-Loop (Critical Actions)

For **CRITICAL** incidents affecting SCADA safety, these actions require manual analyst approval:

| Action | Description | Why Approval Required |
|--------|-------------|----------------------|
| `ISOLATE_PLC` | Isolate PLC from network | Could stop water treatment process |
| `REVOKE_CREDENTIALS` | Revoke user credentials | Could lock out legitimate operators |
| `LOCK_SCADA_SERVER` | Lock SCADA HMI server access | Could prevent emergency manual control |

**Approval API:**
```json
POST /api/soar/approve
{ "incident_id": "INC-xxx", "action": "ISOLATE_PLC", "analyst": "SOC_Analyst_L2" }
```

### 16.6 VirusTotal Integration

| Setting | Value |
|---------|-------|
| API Version | v3 |
| API Key | Set via `VT_API_KEY` environment variable |
| Endpoint | `https://www.virustotal.com/api/v3/ip_addresses/{ip}` |
| Cache Duration | 30 minutes |
| Rate Limit | 4 requests/minute (free tier) |

**Data Extracted from VirusTotal:**
- Malicious engine count / Total engines
- Suspicious flag, Reputation score
- Country, AS Owner
- Direct link to VT report

### 16.7 Shuffle SOAR Integration (Cloud)

| Setting | Value |
|---------|-------|
| Platform | Shuffle (Cloud — shuffler.io) |
| Workflow Name | `SCADA SOC - Incident Response` |
| Workflow ID | `0e727e93-41c8-4edb-baac-97aad31dc463` |
| Webhook Trigger | `https://shuffler.io/api/v1/hooks/webhook_209259ef-...` |
| API Key | Set via `SHUFFLE_API_KEY` environment variable |

**Shuffle Workflow Nodes:**

```
Webhook (trigger) → VirusTotal (GET) → MISP (POST) → Send_Alert (POST)
```

| Node | App | Action | Description |
|------|-----|--------|-------------|
| **Webhook_1** | Trigger | Webhook | Receives alert JSON from SOAR engine with `source_ip`, `event_type`, `mitre_id`, etc. |
| **VirusTotal** | HTTP | GET | Queries `virustotal.com/api/v3/ip_addresses/$exec.source_ip` with API key header |
| **MISP** | HTTP | POST | Searches MISP via ngrok tunnel for IOCs matching `$exec.source_ip` |
| **Send_Alert** | HTTP | POST | Sends alert notification with threat details, VT/MISP status back to SOC |

**Data sent to Shuffle webhook:**
```json
{
  "source_ip": "203.0.113.42",
  "event_type": "LOGIN_ATTEMPT",
  "description": "Failed login attempt for user 'root' from external IP",
  "threat_severity": "CRITICAL",
  "threat_intel_tag": "THREAT_INTEL_MATCH",
  "mitre_id": "T1078",
  "mitre_technique": "Valid Accounts",
  "username": "root",
  "status": "FAILED",
  "incident_id": "INC-1776174704164",
  "classification": "THREAT_INTEL_MATCH_ACTIVITY",
  "risk_score": 100,
  "ioc_type": "FAILED_AUTH+MALICIOUS_IP",
  "ioa_type": "SUSPICIOUS_LOGIN"
}
```

### 16.8 MTTD / MTTR Metrics

| Metric | Description | Measured |
|--------|-------------|----------|
| **MTTD** (Mean Time to Detect) | Time from event occurrence to detection by SOAR | ~1 second (automated) |
| **MTTR** (Mean Time to Respond) | Time from detection to response actions completed | ~1–2 seconds (automated) |

**Comparison with manual SOC:**
| Metric | Manual SOC | Automated SOAR | Improvement |
|--------|-----------|---------------|-------------|
| MTTD | 15–30 minutes | **~1 second** | **99.9% faster** |
| MTTR | 1–4 hours | **~2 seconds** | **99.9% faster** |

### 16.9 Incident Report Structure

Each incident generates a JSON report saved to `logs/reports/`:

```json
{
  "report_id": "RPT-1776174705954",
  "incident_id": "INC-1776174704164",
  "severity": "HIGH",
  "classification": "THREAT_INTEL_MATCH_ACTIVITY",
  "summary": {
    "title": "HIGH Security Incident: THREAT_INTEL_MATCH_ACTIVITY",
    "source_ip": "203.0.113.42",
    "mttd_seconds": 1,
    "mttr_seconds": 1
  },
  "enrichment_results": {
    "virustotal": { "malicious": false, "malicious_count": 0, "total_engines": 94 },
    "misp": { "found": false },
    "internal_cti": { "mitre_id": "T1078", "risk_score": 100 }
  },
  "mitre_attack": { "technique_id": "T1078", "tactic": "Initial Access" },
  "response_actions": ["LOG_COLLECTION", "BLOCK_IP", "TERMINATE_VPN", "CREATE_TICKET", "SEND_NOTIFICATIONS"],
  "timeline": [ ... ],
  "recommendations": [ ... ]
}
```

---

## 17. SECURITY TOOLS INTEGRATION SUMMARY

| Tool | Purpose | Integration Method |
|------|---------|-------------------|
| **Wazuh SIEM** | Centralized log analysis, alerting, compliance | UDP Syslog (port 514) + Agent file monitoring |
| **MISP** | Threat Intelligence sharing and IOC enrichment | HTTPS REST API (port 8443) |
| **MITRE ATT&CK** | Attack technique classification (ICS framework) | Embedded in rules and enrichment engine |
| **VirusTotal** | IP reputation checking | HTTPS REST API (v3) |
| **Shuffle SOAR** | Cloud-based orchestration and automation | Webhook (HTTPS) |

---

## 18. PROJECT FILE STRUCTURE

```
soc-mini/
├── backend/
│   ├── server.js            # Main Express + WebSocket server (with SOAR routes)
│   ├── config.js            # Configuration (SCADA, Wazuh, MISP, VT, Shuffle)
│   ├── simulator.js         # SCADA event and attack scenario generator
│   ├── enricher.js          # Log enrichment engine (CTI, IoC, IoA, MITRE)
│   ├── wazuh-sender.js      # Sends logs to Wazuh via UDP syslog + file
│   ├── threat-hunter.js     # Proactive threat hunting (3 hypotheses + 3 supporting)
│   ├── misp-client.js       # MISP API client for threat intelligence
│   ├── virustotal-client.js # VirusTotal API client for IP reputation
│   └── soar-engine.js       # SOAR engine — incident response automation
├── frontend/
│   ├── index.html           # SOC Dashboard HTML
│   ├── app.js               # Dashboard logic (WebSocket, charts, hunt display)
│   └── styles.css           # Dark-theme SOC dashboard styling
├── wazuh-rules/
│   ├── scada_rules.xml      # Custom Wazuh detection rules (100100–100199)
│   ├── ossec_agent.conf     # Wazuh Agent configuration
│   └── test_log.sh          # Script to test rules via wazuh-logtest
├── logs/
│   ├── scada-events.log     # SCADA log file monitored by Wazuh Agent
│   ├── soc-alerts.log       # Local alert log
│   └── reports/             # Auto-generated incident reports (Phase 4)
│       └── RPT-*.json       # JSON incident reports with timeline & enrichment
├── package.json             # Node.js dependencies
└── PROJECT_DOCUMENTATION.md # This file
```

---

## 19. HOW TO RUN

### Prerequisites
- Node.js v18+
- Docker Desktop (for Wazuh Manager and MISP containers)
- Wazuh Agent installed on Windows
- ngrok (for exposing MISP to Shuffle cloud)

### Step 1: Install Dependencies
```bash
cd soc-mini
npm install
```

### Step 2: Deploy Wazuh Rules
```bash
docker cp wazuh-rules/scada_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

### Step 3: Start ngrok (for MISP → Shuffle)
```bash
ngrok http https://localhost:8443
```

### Step 4: Start the SOC Server
```powershell
$env:MISP_API_KEY='your_key'
$env:VT_API_KEY='your_key'
node backend/server.js
```

### Step 5: Restart Wazuh Agent
```powershell
# In Admin PowerShell:
Restart-Service WazuhSvc -Force
```

### Step 6: Access Dashboards
- **SOC Dashboard:** http://localhost:3000
- **Wazuh Dashboard:** https://localhost (Docker)
- **MISP Dashboard:** https://localhost:8443
- **Shuffle SOAR:** https://shuffler.io/workflows/0e727e93-41c8-4edb-baac-97aad31dc463

---

## 20. API REFERENCE

### Simulation & Events

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/simulation/start` | POST | Start normal SCADA simulation |
| `/api/simulation/stop` | POST | Stop normal simulation |
| `/api/scenarios` | GET | List available attack scenarios |
| `/api/attack/start` | POST | Launch attack scenario (`{ "scenario": "brute_force" }`) |
| `/api/attack/stop` | POST | Stop attack scenario |
| `/api/events` | GET | Get recent events (query: `?severity=CRITICAL&limit=50`) |
| `/api/hunt` | GET | Run all threat hunts |
| `/api/metrics` | GET | Get SOC metrics summary |

### MISP Integration

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/misp/status` | GET | MISP connection status and sync stats |
| `/api/misp/sync` | POST | Force sync indicators from MISP |
| `/api/misp/search/:indicator` | GET | Search indicator in MISP database |
| `/api/misp/events` | GET | Fetch recent MISP events |

### SOAR / Incident Response (Phase 4)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/webhook/wazuh` | POST | Wazuh alert webhook (Shuffle → SOC) |
| `/api/soar/incidents` | GET | List all incidents |
| `/api/soar/incidents/:id` | GET | Get specific incident with full timeline |
| `/api/soar/approvals` | GET | List pending human approvals |
| `/api/soar/approve` | POST | Approve critical action `{ "incident_id", "action", "analyst" }` |
| `/api/soar/deny` | POST | Deny critical action `{ "incident_id", "action", "reason" }` |
| `/api/soar/stats` | GET | SOAR metrics: incidents, MTTD, MTTR, blocked IPs |
| `/api/soar/response-log` | GET | Full response action log |

### VirusTotal

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/vt/ip/:ip` | GET | VirusTotal IP reputation check |
| `/api/vt/stats` | GET | VT API usage statistics |

---

*Project by: Vinod G R*
*Date: April 2026*
*Course: SCADA Security / Security Operations Center*
*Phase 4: Incident Response & SOAR Automation — Complete*

---

## 21. SOC DASHBOARD — SOAR ALERTS TAB

The dashboard includes a dedicated **SOAR Alerts** tab with:

### Dashboard Tabs

| Tab | Description |
|-----|-------------|
| **Dashboard** | Real-time KPIs, severity distribution, event types, top IPs, live event feed |
| **Event Log** | Searchable/filterable table of all SCADA events |
| **Attack Sim** | Launch simulated attack scenarios (brute force, malware, lateral movement) |
| **SOAR Alerts** | Incident response dashboard with Shuffle integration |
| **Settings** | Wazuh connection configuration, system controls |

### SOAR Alerts Tab Features

| Feature | Description |
|---------|-------------|
| **Total Incidents** | Count of all Shuffle workflow executions |
| **Critical Count** | Number of CRITICAL severity incidents (brute force, malware, lateral movement) |
| **Avg MTTD** | Mean Time to Detect — automated detection speed |
| **Avg MTTR** | Mean Time to Respond — automated response speed |
| **VT Scans** | Count of VirusTotal IP reputation scans performed via Shuffle |
| **Pending Approvals** | Number of actions awaiting analyst approval |
| **Shuffle Alert Feed** | **Real data from Shuffle Cloud API** — each entry shows the actual workflow execution with VT results (engine count, malicious score, reputation), MISP lookup, MITRE ATT&CK ID, and workflow node completion |
| **Pending Approvals Panel** | Approve/Deny buttons for critical SCADA actions (Isolate PLC, Revoke Credentials, Lock Server) |

> **Important:** All alerts in the SOAR tab are fetched directly from the Shuffle Cloud API
> (`GET /api/v1/workflows/{id}/executions`). They are NOT locally generated. Each alert
> represents a real Shuffle workflow execution with genuine VirusTotal and MISP enrichment results.

### Approve/Deny Actions

The Approve/Deny buttons in the Pending Approvals section are **simulated responses** appropriate for a lab/educational environment:
- **Approve** → Marks the action as `COMPLETED` in the SOAR engine and logs the analyst's name
- **Deny** → Marks the action as `DENIED` with the analyst's reason
- In a **production environment**, these would integrate with real firewall APIs, PLC controllers, Active Directory, and VPN gateways

---

## 22. VERIFIED TEST RESULTS

Full end-to-end testing was conducted on **April 14, 2026**.

### Pipeline Verification

| Step | Component | Status | Evidence |
|------|-----------|--------|----------|
| 1 | Alert Trigger | ✅ PASS | Alerts auto-created from brute force attacks |
| 2 | VirusTotal Enrichment | ✅ PASS | HTTP 200 — 94 engines scanned, malicious/clean scores returned |
| 3 | MISP Enrichment | ✅ PASS | HTTP 200 — IOC search via ngrok tunnel |
| 4 | Decision Logic | ✅ PASS | CRITICAL (brute force), LOW (general) correctly classified |
| 5 | Shuffle Workflow | ✅ PASS | All 3 nodes completed: VT → MISP → Send_Alert |
| 6 | Dashboard Display | ✅ PASS | Real Shuffle Cloud data shown with ☁️ source indicator |
| 7 | Human Approval | ✅ PASS | Approve/Deny buttons functional (simulated in lab) |
| 8 | Report Generation | ✅ PASS | JSON reports saved to logs/reports/ |

### Performance Metrics

| Metric | Value |
|--------|-------|
| Total Shuffle Executions | 100+ |
| Critical Incidents | 7 |
| VirusTotal Scans | 30 (HTTP 200, 94 engines each) |
| MISP Lookups | 30 |
| Pending Approvals | 0 (all resolved) |
| Mean Time to Detect (MTTD) | **< 1 second** |
| Mean Time to Respond (MTTR) | **< 1 second** |
| Shuffle Nodes per Execution | 3 (VT → MISP → Send_Alert) |

### Human-in-the-Loop Verification

```
Approval Test:
  Incident: INC-1776176456822
  Classification: BRUTE_FORCE_FROM_KNOWN_THREAT_ACTOR
  Action: ISOLATE_PLC
  Analyst: SOC_Analyst_L2
  Result: ✅ APPROVED → PLC isolated from network
```

