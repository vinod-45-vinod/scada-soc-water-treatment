# SOC-Mini: SCADA/ICS Security Operations Center

> A fully functional SOC for monitoring and protecting SCADA/ICS environments, simulating a **Municipal Water Treatment Plant**.

---

## Features

- **Real-time SCADA event simulation** — pH, chlorine, turbidity, flow rate, pressure, temperature
- **Log enrichment** — CTI, IoC, IoA, and MITRE ATT&CK for ICS mapping
- **Threat Hunting** — 6 formal hunt hypotheses (brute-force, lateral movement, data exfil, etc.)
- **SOAR integration** — Shuffle-powered automated response playbooks
- **Threat Intelligence** — MISP integration for IOC sharing; VirusTotal enrichment
- **WebSocket Dashboard** — Live SOC monitoring UI (HTML/CSS/JS)
- **Wazuh SIEM** — Centralized log analysis & alerting via Docker

---

## Architecture

```
SCADA Simulator  ──▶  Log Enricher  ──▶  Wazuh SIEM (Docker :514)
      │                    │                      │
      ▼                    ▼                      ▼
WebSocket Dashboard   Threat Hunter          Wazuh Agent
      (Port 3000)      (6 Hypotheses)        (Windows)
                            │
                            ▼
                     MISP (Docker :8443)
```

| Component | Technology | Port | Purpose |
|---|---|---|---|
| Backend Server | Node.js (Express + WS) | 3000 | Event processing, API, real-time dashboard |
| SCADA Simulator | Node.js | — | Generates realistic SCADA events & attack scenarios |
| Log Enricher | Node.js | — | CTI, IoC, IoA, MITRE ATT&CK enrichment |
| Wazuh Manager | Docker | 514/UDP, 55000 | SIEM — centralized log analysis & alerting |
| MISP | Docker | 8443 | Threat Intelligence Platform — IOC sharing |
| Threat Hunter | Node.js | — | Proactive threat hunting |
| Frontend | HTML/CSS/JS | 3000 | Real-time SOC monitoring interface |

---

## Quick Start

### Prerequisites

- [Node.js](https://nodejs.org/) >= 18.x
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) >= 4.x
- npm >= 9.x

### 1. Clone & Install

```bash
git clone https://github.com/vinod-45-vinod/scada-soc-water-treatment.git
cd soc-mini
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your actual API keys
```

Required variables in `.env`:

| Variable | Description |
|---|---|
| `MISP_URL` | MISP instance URL (default: `https://localhost:8443`) |
| `MISP_API_KEY` | Your MISP API key |
| `VT_API_KEY` | VirusTotal API key |
| `SHUFFLE_WEBHOOK_URL` | Shuffle SOAR webhook URL |
| `SHUFFLE_API_KEY` | Shuffle SOAR API key |
| `SHUFFLE_WORKFLOW_ID` | Shuffle workflow ID |

### 3. Start Docker Services

```bash
# Wazuh (SIEM)
docker run -d --name wazuh -p 514:514/udp -p 55000:55000 wazuh/wazuh-manager

# MISP
docker run -d --name misp -p 8443:443 misp/misp
```

### 4. Run

```bash
# Start the SOC server + dashboard
npm start

# Or run in dev mode
npm run dev

# In a separate terminal — start the SCADA event simulator
npm run simulate

# Run threat hunting analysis
npm run hunt
```

Open the dashboard at **http://localhost:3000**

---

## Project Structure

```
soc-mini/
├── backend/
│   ├── server.js           # Express + WebSocket server
│   ├── simulator.js        # SCADA event simulator
│   ├── enricher.js         # Log enrichment (CTI, MITRE)
│   ├── threat-hunter.js    # Proactive threat hunting
│   ├── soar-engine.js      # Shuffle SOAR integration
│   ├── misp-client.js      # MISP threat intel client
│   ├── virustotal-client.js# VirusTotal enrichment
│   ├── wazuh-sender.js     # Wazuh syslog forwarder
│   └── config.js           # Centralised configuration
├── frontend/
│   ├── index.html          # Dashboard UI
│   ├── app.js              # Dashboard logic
│   └── styles.css          # Dashboard styles
├── logs/                   # Runtime log output (git-ignored)
│   └── reports/            # Generated incident reports (git-ignored)
├── wazuh-rules/
│   ├── scada_rules.xml     # Custom Wazuh detection rules
│   ├── ossec_agent.conf    # Wazuh agent config
│   ├── setup_agent.ps1     # Windows agent setup script
│   └── SETUP.md            # Wazuh setup guide
├── .env.example            # Environment variable template
├── package.json
└── PROJECT_DOCUMENTATION.md
```

---

## MITRE ATT&CK for ICS Coverage

| Technique ID | Technique | Tactic |
|---|---|---|
| T1078 | Valid Accounts | Initial Access |
| T1110 | Brute Force | Credential Access |
| T0859 | Valid Accounts (ICS) | Execution |
| T0855 | Unauthorized Command Message | Impair Process Control |
| T0832 | Manipulation of View | Evasion |
| T0829 | Modify Control Logic | Impair Process Control |
| T0866 | Exploitation of Remote Services | Lateral Movement |
| T0882 | Theft of Operational Information | Collection |

---

## Wazuh Agent Setup (Windows)

See [`wazuh-rules/SETUP.md`](wazuh-rules/SETUP.md) for detailed Wazuh agent installation and configuration instructions.

---

## Documentation

Full project documentation, design decisions, and component details are in [`PROJECT_DOCUMENTATION.md`](PROJECT_DOCUMENTATION.md).
