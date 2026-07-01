/**
 * SOC-Mini Configuration
 * Municipal Water Treatment Plant SCADA/ICS SOC System
 */

const config = {
  // Server Configuration
  server: {
    port: 3000,
    host: '0.0.0.0',
    wsPort: 3001,
  },

  // Wazuh Manager (Docker) Configuration
  wazuh: {
    host: '127.0.0.1',       // Docker host IP - change if needed
    udpPort: 514,             // Syslog UDP port
    managerPort: 55000,       // Wazuh API port
  },

  // MISP (Malware Information Sharing Platform) Configuration
  misp: {
    url: process.env.MISP_URL || 'https://localhost:8443',
    apiKey: process.env.MISP_API_KEY,  // Required: set MISP_API_KEY in .env
    verifySsl: false,          // false for self-signed certs in Docker containers
    syncIntervalMs: 60000,     // Sync indicators every 60 seconds
    pushAlerts: true,          // Push critical SCADA alerts back to MISP
    pushThreshold: 'CRITICAL', // Minimum severity to push to MISP
  },

  // VirusTotal API Configuration
  virustotal: {
    apiKey: process.env.VT_API_KEY,  // Required: set VT_API_KEY in .env
  },

  // Shuffle SOAR Configuration
  shuffle: {
    webhookUrl: process.env.SHUFFLE_WEBHOOK_URL,  // Required: set SHUFFLE_WEBHOOK_URL in .env
    apiKey: process.env.SHUFFLE_API_KEY,           // Required: set SHUFFLE_API_KEY in .env
    workflowId: process.env.SHUFFLE_WORKFLOW_ID || '',
    enabled: true,
  },


  logs: {
    scadaLogFile: './logs/scada-events.log',
    alertLogFile: './logs/soc-alerts.log',
    huntLogFile: './logs/threat-hunt.log',
  },

  // SCADA Plant Configuration
  scada: {
    plantName: 'Municipal Water Treatment Plant - Unit 7',
    // Normal operating ranges
    sensors: {
      pH: { min: 6.5, max: 8.5, unit: 'pH', critical_low: 5.0, critical_high: 10.0 },
      chlorine: { min: 0.2, max: 4.0, unit: 'mg/L', critical_low: 0.0, critical_high: 6.0 },
      turbidity: { min: 0.0, max: 1.0, unit: 'NTU', critical_low: 0.0, critical_high: 5.0 },
      flow_rate: { min: 100, max: 500, unit: 'GPM', critical_low: 50, critical_high: 800 },
      pressure: { min: 30, max: 80, unit: 'PSI', critical_low: 15, critical_high: 120 },
      temperature: { min: 15, max: 30, unit: '°C', critical_low: 5, critical_high: 45 },
    },
    plcs: [
      { id: 'PLC-001', name: 'Chemical Dosing Controller', zone: 'CHEMICAL' },
      { id: 'PLC-002', name: 'Filtration System Controller', zone: 'FILTRATION' },
      { id: 'PLC-003', name: 'Pump Station Controller', zone: 'PUMPING' },
      { id: 'PLC-004', name: 'Distribution Valve Controller', zone: 'DISTRIBUTION' },
    ],
    hmi_stations: [
      { id: 'HMI-01', name: 'Main Control Room', operator: 'operator1' },
      { id: 'HMI-02', name: 'Remote Monitoring', operator: 'operator2' },
      { id: 'HMI-03', name: 'Engineering Workstation', operator: 'engineer1' },
    ],
  },

  // Threat Intelligence
  threatIntel: {
    // Simulated malicious IPs (like VirusTotal matches)
    maliciousIPs: [
      '198.51.100.23',
      '203.0.113.42',
      '192.0.2.99',
      '198.51.100.77',
      '203.0.113.15',
    ],
    // Known benign IPs (internal network)
    internalIPs: [
      '10.0.1.10',
      '10.0.1.20',
      '10.0.1.30',
      '10.0.1.50',
      '10.0.2.100',
      '172.16.0.5',
    ],
    // Suspicious IPs (not confirmed malicious but flagged)
    suspiciousIPs: [
      '45.33.32.156',
      '104.16.100.29',
    ],
  },

  // MITRE ATT&CK Mappings (ICS Framework)
  mitre: {
    LOGIN_ATTEMPT: {
      id: 'T1078',
      technique: 'Valid Accounts',
      tactic: 'Initial Access',
      url: 'https://attack.mitre.org/techniques/T1078/',
    },
    BRUTE_FORCE: {
      id: 'T1110',
      technique: 'Brute Force',
      tactic: 'Credential Access',
      url: 'https://attack.mitre.org/techniques/T1110/',
    },
    PLC_COMMAND: {
      id: 'T0859',
      technique: 'Valid Accounts (ICS)',
      tactic: 'Execution',
      url: 'https://attack.mitre.org/techniques/T0859/',
    },
    UNAUTHORIZED_PLC: {
      id: 'T0855',
      technique: 'Unauthorized Command Message',
      tactic: 'Impair Process Control',
      url: 'https://attack.mitre.org/techniques/T0855/',
    },
    SENSOR_ANOMALY: {
      id: 'T0832',
      technique: 'Manipulation of View',
      tactic: 'Evasion',
      url: 'https://attack.mitre.org/techniques/T0832/',
    },
    MALWARE_DETECTED: {
      id: 'T0829',
      technique: 'Modify Control Logic',
      tactic: 'Impair Process Control',
      url: 'https://attack.mitre.org/techniques/T0829/',
    },
    LATERAL_MOVEMENT: {
      id: 'T0866',
      technique: 'Exploitation of Remote Services',
      tactic: 'Lateral Movement',
      url: 'https://attack.mitre.org/techniques/T0866/',
    },
    DATA_EXFIL: {
      id: 'T0882',
      technique: 'Theft of Operational Information',
      tactic: 'Collection',
      url: 'https://attack.mitre.org/techniques/T0882/',
    },
  },

  // Attack stages for kill chain
  attackStages: [
    'Reconnaissance',
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Lateral Movement',
    'Collection',
    'Impact',
  ],

  // Simulation intervals (ms)
  simulation: {
    normalEventInterval: 3000,    // Normal events every 3 seconds
    attackEventInterval: 1500,    // Attack events every 1.5 seconds
    sensorReadInterval: 2000,     // Sensor readings every 2 seconds
    attackScenarioDuration: 30000, // Attack scenario lasts 30 seconds
  },
};

module.exports = config;
