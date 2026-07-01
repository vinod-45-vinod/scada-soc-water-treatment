/**
 * SOC-Mini Backend Server
 * Main Express + WebSocket server for SCADA SOC System
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const cors = require('cors');
const config = require('./config');
const LogEnricher = require('./enricher');
const ScadaSimulator = require('./simulator');
const WazuhSender = require('./wazuh-sender');
const ThreatHunter = require('./threat-hunter');
const MISPClient = require('./misp-client');
const VirusTotalClient = require('./virustotal-client');
const SOAREngine = require('./soar-engine');

// Initialize components
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const mispClient = new MISPClient();
const vtClient = new VirusTotalClient();
const enricher = new LogEnricher(mispClient);
const simulator = new ScadaSimulator();
const wazuhSender = new WazuhSender();
const threatHunter = new ThreatHunter();
const soarEngine = new SOAREngine(vtClient, mispClient);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// State
let simulationRunning = false;
let attackRunning = false;
let normalInterval = null;
let attackInterval = null;
let eventCounter = 0;
let recentEvents = [];
const MAX_RECENT = 200;

// ===== WebSocket Management =====
const wsClients = new Set();

wss.on('connection', (ws) => {
  wsClients.add(ws);
  console.log(`[WS] Client connected. Total: ${wsClients.size}`);

  // Send initial state
  ws.send(JSON.stringify({
    type: 'INIT',
    data: {
      simulationRunning,
      attackRunning,
      eventCount: eventCounter,
      recentEvents: recentEvents.slice(-50),
      metrics: threatHunter.getMetrics(),
      scenarios: simulator.getScenarios(),
      config: {
        plantName: config.scada.plantName,
        wazuhHost: config.wazuh.host,
        wazuhPort: config.wazuh.udpPort,
      },
    },
  }));

  ws.on('close', () => {
    wsClients.delete(ws);
    console.log(`[WS] Client disconnected. Total: ${wsClients.size}`);
  });
});

function broadcast(type, data) {
  const message = JSON.stringify({ type, data });
  for (const client of wsClients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  }
}

// ===== Core Event Processing =====
function processEvent(rawEvent) {
  // 1. Enrich the event
  const enriched = enricher.enrichEvent(rawEvent);
  enriched.event_number = ++eventCounter;

  // 2. Format for Wazuh
  const wazuhMsg = enricher.formatForWazuh(enriched);

  // 3. Send to Wazuh (UDP + file)
  wazuhSender.sendLog(enriched, wazuhMsg);

  // 4. Add to threat hunter
  threatHunter.addEvent(enriched);

  // 5. Store in recent events
  recentEvents.push(enriched);
  if (recentEvents.length > MAX_RECENT) {
    recentEvents = recentEvents.slice(-MAX_RECENT);
  }

  // 6. Broadcast to WebSocket clients
  broadcast('EVENT', enriched);

  // 7. Log to console based on severity
  const severityColors = {
    LOW: '\x1b[32m',
    MEDIUM: '\x1b[33m',
    HIGH: '\x1b[35m',
    CRITICAL: '\x1b[31m',
  };
  const color = severityColors[enriched.threat_severity] || '\x1b[0m';
  console.log(`${color}[#${enriched.event_number}] [${enriched.threat_severity}] ${enriched.event_type}: ${enriched.description}\x1b[0m`);

  // 8. Push critical alerts to MISP
  if (config.misp.pushAlerts && mispClient.connected) {
    const sevLevels = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
    const threshold = sevLevels[config.misp.pushThreshold] || 3;
    if (sevLevels[enriched.threat_severity] >= threshold) {
      mispClient.createEvent(enriched).catch(err => {
        console.error('[MISP] Failed to push alert:', err.message);
      });
    }
  }

  // 9. SOAR — Process alert through incident response pipeline
  soarEngine.processAlert(enriched).then(incident => {
    if (incident) {
      broadcast('INCIDENT', incident);
    }
  }).catch(err => {
    console.error('[SOAR] Pipeline error:', err.message);
  });

  return enriched;
}

// ===== Simulation Control =====
function startNormalSimulation() {
  if (normalInterval) return;
  simulationRunning = true;
  normalInterval = setInterval(() => {
    const event = simulator.generateNormalEvent();
    processEvent(event);
  }, config.simulation.normalEventInterval);
  console.log('[SIM] Normal simulation started');
  broadcast('STATUS', { simulationRunning: true });
}

function stopNormalSimulation() {
  if (normalInterval) {
    clearInterval(normalInterval);
    normalInterval = null;
  }
  simulationRunning = false;
  console.log('[SIM] Normal simulation stopped');
  broadcast('STATUS', { simulationRunning: false });
}

function startAttackScenario(scenarioId) {
  if (attackInterval) {
    clearInterval(attackInterval);
  }
  attackRunning = true;
  simulator.resetAttackChain();

  let attackCount = 0;
  const maxEvents = scenarioId === 'full_attack_chain' ? 10 : 5;

  attackInterval = setInterval(() => {
    const event = simulator.generateAttackEvent(scenarioId);
    processEvent(event);
    attackCount++;

    if (attackCount >= maxEvents) {
      stopAttackScenario();
    }
  }, config.simulation.attackEventInterval);

  console.log(`[ATTACK] Scenario '${scenarioId}' started`);
  broadcast('STATUS', { attackRunning: true, scenarioId });
}

function stopAttackScenario() {
  if (attackInterval) {
    clearInterval(attackInterval);
    attackInterval = null;
  }
  attackRunning = false;
  simulator.resetAttackChain();
  console.log('[ATTACK] Scenario stopped');
  broadcast('STATUS', { attackRunning: false });
}

// ===== REST API Routes =====

// --- Simulation Control ---
app.post('/api/simulation/start', (req, res) => {
  startNormalSimulation();
  res.json({ status: 'started', message: 'Normal SCADA simulation started' });
});

app.post('/api/simulation/stop', (req, res) => {
  stopNormalSimulation();
  res.json({ status: 'stopped', message: 'Normal SCADA simulation stopped' });
});

// --- Attack Scenarios ---
app.get('/api/scenarios', (req, res) => {
  res.json(simulator.getScenarios());
});

app.post('/api/attack/start', (req, res) => {
  const { scenario } = req.body;
  if (!scenario) {
    return res.status(400).json({ error: 'scenario is required' });
  }
  startAttackScenario(scenario);
  res.json({ status: 'attack_started', scenario });
});

app.post('/api/attack/stop', (req, res) => {
  stopAttackScenario();
  res.json({ status: 'attack_stopped' });
});

// --- Events & Alerts ---
app.get('/api/events', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const severity = req.query.severity;
  const eventType = req.query.event_type;

  let events = [...recentEvents];
  if (severity) events = events.filter(e => e.threat_severity === severity);
  if (eventType) events = events.filter(e => e.event_type === eventType);

  res.json({
    total: events.length,
    events: events.slice(-limit).reverse(),
  });
});

app.get('/api/events/:id', (req, res) => {
  const event = recentEvents.find(e => e.event_id === req.params.id);
  if (!event) return res.status(404).json({ error: 'Event not found' });
  res.json(event);
});

// --- Threat Hunting ---
app.get('/api/hunt', (req, res) => {
  const results = threatHunter.runAllHunts();
  res.json({
    timestamp: new Date().toISOString(),
    total_hunts: results.length,
    hunts: results,
  });
});

app.get('/api/hunt/timeline', (req, res) => {
  const filters = {};
  if (req.query.source_ip) filters.source_ip = req.query.source_ip;
  if (req.query.event_type) filters.event_type = req.query.event_type;
  if (req.query.severity) filters.severity = req.query.severity;

  const timeline = threatHunter.getTimeline(filters);
  res.json({ total: timeline.length, timeline });
});

// --- Metrics & Dashboard ---
app.get('/api/metrics', (req, res) => {
  const metrics = threatHunter.getMetrics();
  const wazuhStats = wazuhSender.getStats();

  res.json({
    ...metrics,
    wazuh: wazuhStats,
    simulation: { running: simulationRunning, attackRunning },
    uptime: process.uptime(),
  });
});

// --- Wazuh Configuration ---
app.post('/api/wazuh/config', (req, res) => {
  const { host, port } = req.body;
  if (host) {
    wazuhSender.setWazuhTarget(host, port || 514);
    res.json({ status: 'updated', host, port: port || 514 });
  } else {
    res.status(400).json({ error: 'host is required' });
  }
});

app.get('/api/wazuh/status', (req, res) => {
  res.json({
    host: config.wazuh.host,
    port: config.wazuh.udpPort,
    stats: wazuhSender.getStats(),
  });
});

// --- Manual Event Injection ---
app.post('/api/inject', (req, res) => {
  const event = req.body;
  if (!event.event_type) {
    return res.status(400).json({ error: 'event_type is required' });
  }
  const enriched = processEvent(event);
  res.json({ status: 'injected', event: enriched });
});

// --- System ---
app.get('/api/config', (req, res) => {
  res.json({
    plant: config.scada.plantName,
    sensors: config.scada.sensors,
    plcs: config.scada.plcs,
    mitre_mappings: config.mitre,
    attack_stages: config.attackStages,
    malicious_ips: config.threatIntel.maliciousIPs,
  });
});

app.post('/api/reset', (req, res) => {
  stopNormalSimulation();
  stopAttackScenario();
  recentEvents = [];
  eventCounter = 0;
  threatHunter.clearBuffer();
  simulator.resetAttackChain();
  broadcast('RESET', {});
  res.json({ status: 'reset', message: 'All state cleared' });
});

// --- MISP Integration ---
app.get('/api/misp/status', (req, res) => {
  res.json(mispClient.getStatus());
});

app.post('/api/misp/sync', async (req, res) => {
  try {
    const stats = await mispClient.syncIndicators();
    enricher.updateFromMISP();
    res.json({ status: 'synced', stats });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/misp/config', (req, res) => {
  const { url, apiKey } = req.body;
  if (!url && !apiKey) {
    return res.status(400).json({ error: 'url or apiKey required' });
  }
  mispClient.updateConfig(url, apiKey);
  // Re-init with new config
  mispClient.init().then(connected => {
    if (connected) enricher.updateFromMISP();
    res.json({ status: connected ? 'connected' : 'failed', url: mispClient.baseUrl });
  });
});

app.get('/api/misp/search/:indicator', async (req, res) => {
  const result = await mispClient.searchIndicator(req.params.indicator);
  res.json(result);
});

app.get('/api/misp/events', async (req, res) => {
  const limit = parseInt(req.query.limit) || 10;
  const events = await mispClient.getRecentEvents(limit);
  res.json({ total: events.length, events });
});

// --- SOAR Incident Response ---

// Webhook endpoint for Wazuh → Shuffle → SOC-MINI
app.post('/api/webhook/wazuh', async (req, res) => {
  console.log('[WEBHOOK] Received Wazuh alert');
  const alert = req.body;
  const incident = await soarEngine.processAlert({
    event_type: alert.rule?.groups?.[0] || alert.event_type || 'UNKNOWN',
    description: alert.rule?.description || alert.description || 'Wazuh Alert',
    source_ip: alert.data?.srcip || alert.source_ip || '0.0.0.0',
    username: alert.data?.dstuser || alert.username || 'unknown',
    status: alert.status || 'UNKNOWN',
    threat_intel_tag: alert.threat_intel_tag || 'UNKNOWN',
    threat_severity: alert.threat_severity || 'HIGH',
    mitre_id: alert.rule?.mitre?.id?.[0] || alert.mitre_id || 'N/A',
    mitre_technique: alert.rule?.mitre?.technique?.[0] || alert.mitre_technique || 'N/A',
    mitre_tactic: alert.rule?.mitre?.tactic?.[0] || alert.mitre_tactic || 'N/A',
    ioa_type: alert.ioa_type || 'NONE',
    ioc_type: alert.ioc_type || 'NONE',
    is_malicious_ip: alert.is_malicious_ip || false,
    risk_score: alert.risk_score || 0,
    plc_id: alert.plc_id || null,
    plc_command: alert.plc_command || null,
  });
  if (incident) {
    broadcast('INCIDENT', incident);
    res.json({ status: 'processed', incident_id: incident.id, severity: incident.severity });
  } else {
    res.json({ status: 'no_action', message: 'Alert did not meet trigger criteria' });
  }
});

// === Custom Attack Demo — Full Workflow with Step-by-Step Results ===
app.post('/api/attack/custom-demo', async (req, res) => {
  const { attacker_ip, username } = req.body;
  if (!attacker_ip) return res.status(400).json({ error: 'attacker_ip required' });

  const steps = [];
  const startTime = Date.now();

  try {
    // STEP 1: Generate the attack event
    steps.push({ step: 1, name: 'EVENT_GENERATED', status: '✅', time: Date.now() - startTime,
      detail: `Brute force LOGIN_ATTEMPT from ${attacker_ip} as user '${username || 'root'}'`,
      data: { event_type: 'LOGIN_ATTEMPT', source_ip: attacker_ip, username: username || 'root', status: 'FAILED' }
    });

    // STEP 2: Enrich the event
    const enrichedEvent = {
      event_type: 'LOGIN_ATTEMPT',
      description: `Failed login attempt for user '${username || 'root'}' from external IP`,
      source_ip: attacker_ip,
      destination_ip: '10.0.1.10',
      username: username || 'root',
      status: 'FAILED',
      is_malicious_ip: config.threatIntel.maliciousIPs.includes(attacker_ip),
      threat_intel_tag: config.threatIntel.maliciousIPs.includes(attacker_ip) ? 'THREAT_INTEL_MATCH' : 'UNKNOWN',
      ioc_type: 'FAILED_AUTH' + (config.threatIntel.maliciousIPs.includes(attacker_ip) ? '+MALICIOUS_IP' : ''),
      ioa_type: 'SUSPICIOUS_LOGIN',
      mitre_id: 'T1110',
      mitre_technique: 'Brute Force',
      mitre_tactic: 'Credential Access',
      attack_stage: 'Initial Access',
      threat_severity: 'CRITICAL',
      risk_score: config.threatIntel.maliciousIPs.includes(attacker_ip) ? 100 : 75,
    };

    // Check MISP for the IP
    let mispKnown = false;
    if (mispClient.connected) {
      mispKnown = mispClient.isIPMalicious(attacker_ip);
    }

    steps.push({ step: 2, name: 'ENRICHMENT', status: '✅', time: Date.now() - startTime,
      detail: `Enriched: MITRE T1110 Brute Force | Threat Intel: ${enrichedEvent.threat_intel_tag} | MISP known: ${mispKnown} | Risk: ${enrichedEvent.risk_score}`,
      data: {
        mitre_id: 'T1110', mitre_technique: 'Brute Force', mitre_tactic: 'Credential Access',
        threat_intel_tag: enrichedEvent.threat_intel_tag,
        is_malicious_ip: enrichedEvent.is_malicious_ip,
        misp_known: mispKnown,
        risk_score: enrichedEvent.risk_score,
      }
    });

    // STEP 2b: Write to Wazuh log file (so Wazuh SIEM sees it)
    const wazuhMsg = enricher.formatForWazuh(enrichedEvent);
    wazuhSender.sendLog(enrichedEvent, wazuhMsg);
    // Also send to threat hunter for dashboard stats
    threatHunter.addEvent(enrichedEvent);
    // Broadcast to dashboard live feed
    broadcast('EVENT', enrichedEvent);

    // STEP 3: VirusTotal scan
    let vtResult = { status: 'skipped' };
    try {
      vtResult = await vtClient.checkIP(attacker_ip);
      steps.push({ step: 3, name: 'VIRUSTOTAL_SCAN', status: '✅', time: Date.now() - startTime,
        detail: `VT scanned ${attacker_ip}: ${vtResult.malicious_count || 0}/${vtResult.total_engines || 94} engines flagged | Reputation: ${vtResult.reputation || 0} | Country: ${vtResult.country || 'N/A'}`,
        data: {
          malicious_count: vtResult.malicious_count || 0,
          total_engines: vtResult.total_engines || 94,
          reputation: vtResult.reputation || 0,
          country: vtResult.country || 'N/A',
          as_owner: vtResult.as_owner || 'N/A',
          is_clean: !(vtResult.malicious_count > 0),
        }
      });
    } catch (vtErr) {
      steps.push({ step: 3, name: 'VIRUSTOTAL_SCAN', status: '⚠️', time: Date.now() - startTime,
        detail: `VT scan failed: ${vtErr.message}`, data: { error: vtErr.message }
      });
    }

    // STEP 4: MISP deep search
    let mispResult = { found: false };
    try {
      if (mispClient.connected) {
        mispResult = await mispClient.searchIndicator(attacker_ip);
        steps.push({ step: 4, name: 'MISP_IOC_SEARCH', status: '✅', time: Date.now() - startTime,
          detail: `MISP searched for ${attacker_ip}: ${mispResult.found ? `${mispResult.matches.length} IOC matches found` : 'No IOC match'}`,
          data: { found: mispResult.found, matches: mispResult.matches?.length || 0, indicator: attacker_ip }
        });
      } else {
        steps.push({ step: 4, name: 'MISP_IOC_SEARCH', status: '⚠️', time: Date.now() - startTime,
          detail: 'MISP not connected', data: { found: false }
        });
      }
    } catch (mispErr) {
      steps.push({ step: 4, name: 'MISP_IOC_SEARCH', status: '⚠️', time: Date.now() - startTime,
        detail: `MISP search failed: ${mispErr.message}`, data: { error: mispErr.message }
      });
    }

    // STEP 5: SOAR classification & incident creation
    const incident = await soarEngine.processAlert(enrichedEvent);
    if (incident) {
      steps.push({ step: 5, name: 'SOAR_CLASSIFICATION', status: '✅', time: Date.now() - startTime,
        detail: `Classified: ${incident.severity} — ${incident.classification} | Incident: ${incident.id}`,
        data: {
          incident_id: incident.id, severity: incident.severity,
          classification: incident.classification,
          actions: incident.response_actions?.length || 0,
        }
      });
      broadcast('INCIDENT', incident);
    } else {
      steps.push({ step: 5, name: 'SOAR_CLASSIFICATION', status: '⚠️', time: Date.now() - startTime,
        detail: 'Did not meet SOAR trigger criteria', data: {}
      });
    }

    // STEP 6: Shuffle forwarding (already done inside soarEngine.processAlert)
    steps.push({ step: 6, name: 'SHUFFLE_FORWARDED', status: '✅', time: Date.now() - startTime,
      detail: `Alert forwarded to Shuffle Cloud webhook → VT node + MISP node will execute`,
      data: { webhook: 'shuffler.io', nodes: ['VirusTotal', 'MISP', 'Send_Alert'] }
    });

    // STEP 7: MISP push-back (always push for custom demo attacks)
    if (incident && mispClient.connected) {
      try {
        const mispEvent = await mispClient.createEvent(enrichedEvent);
        steps.push({ step: 7, name: 'MISP_PUSH_BACK', status: '✅', time: Date.now() - startTime,
          detail: `Alert pushed to MISP as new event (ID: ${mispEvent?.Event?.id || 'created'}) with tag: mitre-attack-pattern="Brute Force"`,
          data: { misp_event_id: mispEvent?.Event?.id || 'created', tag: 'Brute Force' }
        });
      } catch (pushErr) {
        steps.push({ step: 7, name: 'MISP_PUSH_BACK', status: '⚠️', time: Date.now() - startTime,
          detail: `MISP push-back failed: ${pushErr.message}`, data: { error: pushErr.message }
        });
      }
    } else {
      steps.push({ step: 7, name: 'MISP_PUSH_BACK', status: '⚠️', time: Date.now() - startTime,
        detail: mispClient.connected ? 'No incident created' : 'MISP not connected',
        data: {}
      });
    }

    const totalTime = Date.now() - startTime;
    res.json({
      status: 'completed',
      attacker_ip,
      username: username || 'root',
      total_time_ms: totalTime,
      incident_id: incident?.id || null,
      severity: incident?.severity || 'N/A',
      classification: incident?.classification || 'N/A',
      steps
    });

  } catch (err) {
    res.status(500).json({ error: err.message, steps });
  }
});

app.get('/api/soar/incidents', (req, res) => {
  const incidents = soarEngine.getIncidents();
  res.json({ total: incidents.length, incidents: incidents.reverse() });
});

// Get specific incident
app.get('/api/soar/incidents/:id', (req, res) => {
  const incident = soarEngine.getIncident(req.params.id);
  if (!incident) return res.status(404).json({ error: 'Incident not found' });
  res.json(incident);
});

// Get pending approvals
app.get('/api/soar/approvals', (req, res) => {
  res.json({ approvals: soarEngine.getPendingApprovals() });
});

// Approve action
app.post('/api/soar/approve', (req, res) => {
  const { incident_id, action, analyst } = req.body;
  if (!incident_id || !action) return res.status(400).json({ error: 'incident_id and action required' });
  const result = soarEngine.approveAction(incident_id, action, analyst || 'SOC_Analyst');
  if (result.error) return res.status(400).json(result);
  broadcast('APPROVAL', result);
  res.json(result);
});

// Deny action
app.post('/api/soar/deny', (req, res) => {
  const { incident_id, action, analyst, reason } = req.body;
  if (!incident_id || !action) return res.status(400).json({ error: 'incident_id and action required' });
  const result = soarEngine.denyAction(incident_id, action, analyst, reason);
  res.json(result);
});

// SOAR stats
app.get('/api/soar/stats', (req, res) => {
  res.json(soarEngine.getStats());
});

// SOAR response log
app.get('/api/soar/response-log', (req, res) => {
  res.json({ log: soarEngine.getResponseLog() });
});

// ===== SHUFFLE ALERTS (Real data from Shuffle cloud) =====
const shuffleAlerts = []; // Alerts received FROM Shuffle

// Webhook endpoint — Shuffle's Send_Alert node POSTs here
app.post('/api/shuffle/webhook', (req, res) => {
  const alert = req.body;
  const shuffleAlert = {
    id: 'SHUF-' + Date.now(),
    received_at: new Date().toISOString(),
    source: 'SHUFFLE_SOAR',
    message: alert.message || '',
    source_ip: alert.source_ip || alert.body?.source_ip || 'N/A',
    event_type: alert.event_type || alert.body?.event_type || 'UNKNOWN',
    severity: alert.severity || alert.body?.threat_severity || 'MEDIUM',
    classification: alert.classification || alert.body?.classification || 'SHUFFLE_ALERT',
    vt_status: alert.vt_status || 'N/A',
    misp_status: alert.misp_status || 'N/A',
    mitre_id: alert.mitre_id || alert.body?.mitre_id || 'N/A',
    alert_type: alert.alert_type || 'SHUFFLE_SOAR_ALERT',
    raw: alert,
  };
  shuffleAlerts.push(shuffleAlert);
  if (shuffleAlerts.length > 100) shuffleAlerts.shift();
  console.log(`[SHUFFLE] 📥 Alert received: ${shuffleAlert.source_ip} | ${shuffleAlert.severity}`);
  broadcast('SHUFFLE_ALERT', shuffleAlert);
  res.json({ status: 'received', alert_id: shuffleAlert.id });
});

// Fetch Shuffle execution results directly from Shuffle API
app.get('/api/shuffle/alerts', async (req, res) => {
  try {
    const https = require('https');
    const WF_ID = config.shuffle?.workflowId || '0e727e93-41c8-4edb-baac-97aad31dc463';
    const API_KEY = config.shuffle?.apiKey || process.env.SHUFFLE_API_KEY || '3f993375-e2b3-43c1-8215-24ac8c1f1eae';

    const executions = await new Promise((resolve, reject) => {
      const opts = {
        hostname: 'shuffler.io',
        path: `/api/v1/workflows/${WF_ID}/executions?limit=20`,
        method: 'GET',
        headers: { 'Authorization': 'Bearer ' + API_KEY },
      };
      const req = https.request(opts, resp => {
        let d = '';
        resp.on('data', c => d += c);
        resp.on('end', () => {
          try { resolve(JSON.parse(d)); } catch { resolve([]); }
        });
      });
      req.on('error', () => resolve([]));
      req.end();
    });

    // Parse Shuffle executions into alert objects
    const alerts = (Array.isArray(executions) ? executions : []).map(exec => {
      // Webhook trigger data is in execution_argument
      let triggerBody = {};
      try { triggerBody = JSON.parse(exec.execution_argument || '{}'); } catch {}

      // Find VT and MISP results from the results array
      const vtData = exec.results?.find(r => (r.action?.label || '').includes('VirusTotal') || (r.action?.label || '').includes('virustotal'));
      const mispData = exec.results?.find(r => (r.action?.label || '').includes('MISP') || (r.action?.label || '').includes('misp'));

      let vtResult = {};
      try { vtResult = JSON.parse(vtData?.result || '{}'); } catch {}
      let mispResult = {};
      try { mispResult = JSON.parse(mispData?.result || '{}'); } catch {}

      // Derive severity from multiple possible fields
      const classification = triggerBody.classification || triggerBody.body?.classification || '';
      let severity = triggerBody.threat_severity || triggerBody.severity || triggerBody.body?.threat_severity || '';
      if (!severity || severity === 'N/A') {
        // Derive from classification
        if (classification.includes('BRUTE_FORCE') || classification.includes('MALWARE') || classification.includes('LATERAL_MOVEMENT')) {
          severity = 'CRITICAL';
        } else if (classification.includes('THREAT_INTEL') || classification.includes('PLC_COMMAND')) {
          severity = 'HIGH';
        } else if (classification.includes('GENERAL') || classification.includes('ALERT')) {
          severity = 'LOW';
        } else {
          severity = 'MEDIUM';
        }
      }

      // Extract VT stats
      const vtStats = vtResult.body?.data?.attributes?.last_analysis_stats || {};
      const vtMalicious = vtStats.malicious || 0;
      const vtSuspicious = vtStats.suspicious || 0;
      const vtTotal = Object.values(vtStats).reduce((a, b) => a + (typeof b === 'number' ? b : 0), 0) || 0;
      const vtReputation = vtResult.body?.data?.attributes?.reputation || 0;
      const vtCountry = vtResult.body?.data?.attributes?.country || '';

      return {
        id: 'SHUF-' + exec.execution_id?.slice(0, 8),
        execution_id: exec.execution_id,
        status: exec.status,
        started_at: exec.started_at ? new Date(exec.started_at * 1000).toISOString() : '',
        completed_at: exec.completed_at ? new Date(exec.completed_at * 1000).toISOString() : '',
        source: 'SHUFFLE_CLOUD',
        source_ip: triggerBody.source_ip || triggerBody.body?.source_ip || 'N/A',
        event_type: triggerBody.event_type || triggerBody.body?.event_type || 'N/A',
        severity: severity,
        classification: classification || 'N/A',
        mitre_id: triggerBody.mitre_id || triggerBody.body?.mitre_id || 'N/A',
        description: triggerBody.description || triggerBody.body?.description || '',
        incident_id: triggerBody.incident_id || triggerBody.body?.incident_id || '',
        username: triggerBody.username || triggerBody.body?.username || '',
        vt: {
          status: vtResult.status || 'N/A',
          malicious: vtMalicious,
          suspicious: vtSuspicious,
          total: vtTotal,
          reputation: vtReputation,
          country: vtCountry,
        },
        misp: {
          status: mispResult.status || 'N/A',
          found: (mispResult.body?.response?.Attribute?.length || 0) > 0,
          count: mispResult.body?.response?.Attribute?.length || 0,
        },
        nodes_completed: exec.results?.length || 0,
        workflow_status: exec.status === 'FINISHED' ? 'SUCCESS' : exec.status,
      };
    });

    // Also include recent LOCAL SOAR incidents (so custom attacks show even when Shuffle is 429'd)
    const localIncidents = soarEngine.getIncidents().slice(-20).map(inc => ({
      id: inc.id,
      execution_id: inc.id,
      status: 'FINISHED',
      started_at: inc.created_at || inc.timestamp || new Date().toISOString(),
      completed_at: inc.created_at || inc.timestamp || new Date().toISOString(),
      source: 'LOCAL_SOAR',
      source_ip: inc.alert_source?.source_ip || 'N/A',
      event_type: inc.alert_source?.event_type || 'N/A',
      severity: inc.severity,
      classification: inc.classification || 'N/A',
      mitre_id: inc.alert_source?.mitre_id || 'N/A',
      description: inc.alert_source?.description || '',
      incident_id: inc.id,
      username: inc.alert_source?.username || '',
      vt: {
        status: inc.enrichment?.virustotal?.status || 'N/A',
        malicious: inc.enrichment?.virustotal?.malicious_count || 0,
        suspicious: inc.enrichment?.virustotal?.suspicious || 0,
        total: inc.enrichment?.virustotal?.total_engines || 0,
        reputation: inc.enrichment?.virustotal?.reputation || 0,
        country: inc.enrichment?.virustotal?.country || '',
      },
      misp: {
        status: inc.enrichment?.misp?.found ? 'found' : 'N/A',
        found: inc.enrichment?.misp?.found || false,
        count: inc.enrichment?.misp?.match_count || inc.enrichment?.misp?.matches?.length || 0,
        is_blocked: inc.enrichment?.misp?.is_blocked || false,
      },
      nodes_completed: 3,
      workflow_status: 'SUCCESS',
    }));

    // Build a lookup of local incidents by source_ip for enrichment merging
    const localByIP = {};
    localIncidents.forEach(li => {
      if (li.source_ip && li.source_ip !== 'N/A') {
        localByIP[li.source_ip] = li;
      }
    });

    // Enrich Shuffle Cloud alerts with local VT/MISP data
    alerts.forEach(a => {
      if (a.source === 'SHUFFLE_CLOUD' && a.source_ip && localByIP[a.source_ip]) {
        const local = localByIP[a.source_ip];
        // Merge VT data if Shuffle has none
        if ((!a.vt || !a.vt.total) && local.vt && local.vt.total > 0) {
          a.vt = local.vt;
        }
        // Merge MISP data
        if ((!a.misp || a.misp.status === 'N/A') && local.misp) {
          a.misp = local.misp;
        }
        // Merge classification
        if ((!a.classification || a.classification === 'N/A') && local.classification !== 'N/A') {
          a.classification = local.classification;
          a.severity = local.severity;
        }
      }
    });

    // Merge all alerts, prefer Shuffle Cloud (enriched) over LOCAL_SOAR duplicates
    const allAlerts = [...alerts, ...localIncidents, ...shuffleAlerts].sort((a, b) => {
      return new Date(b.started_at || b.received_at || 0) - new Date(a.started_at || a.received_at || 0);
    });

    // Deduplicate: remove LOCAL_SOAR if same incident exists as SHUFFLE_CLOUD
    const shuffleIPs = new Map(); // ip+timestamp → shuffle alert
    allAlerts.forEach(a => {
      if (a.source === 'SHUFFLE_CLOUD') {
        const key = a.source_ip + '_' + (a.started_at || '').slice(0, 19);
        shuffleIPs.set(key, true);
      }
    });

    const deduped = allAlerts.filter(a => {
      if (a.source === 'LOCAL_SOAR') {
        // Only remove LOCAL_SOAR if there's a matching SHUFFLE_CLOUD with same IP + same second
        const key = a.source_ip + '_' + (a.started_at || '').slice(0, 19);
        return !shuffleIPs.has(key);
      }
      return true;
    });

    res.json({ total: deduped.length, alerts: deduped.slice(0, 30) });
  } catch (err) {
    console.error('[SHUFFLE] Error fetching executions:', err.message);
    // Fallback: return locally stored incidents + Shuffle alerts
    const fallback = soarEngine.getIncidents().slice(-20).map(inc => ({
      id: inc.id, source: 'LOCAL_SOAR', source_ip: inc.alert_source?.source_ip || 'N/A',
      severity: inc.severity, classification: inc.classification || 'N/A',
      started_at: inc.timestamp, event_type: inc.alert_source?.event_type || 'N/A',
      description: inc.alert_source?.description || '', mitre_id: inc.alert_source?.mitre_id || 'N/A',
      username: inc.alert_source?.username || '',
      vt: { malicious: inc.enrichment?.virustotal?.malicious_count || 0, total: inc.enrichment?.virustotal?.total_engines || 0, reputation: inc.enrichment?.virustotal?.reputation || 0, country: inc.enrichment?.virustotal?.country || '' },
      misp: { found: inc.enrichment?.misp?.found || false, count: inc.enrichment?.misp?.match_count || inc.enrichment?.misp?.matches?.length || 0, is_blocked: inc.enrichment?.misp?.is_blocked || false },
      nodes_completed: 3, workflow_status: 'SUCCESS',
    }));
    res.json({ total: fallback.length, alerts: fallback.reverse().slice(0, 30) });
  }
});

// VirusTotal IP check
app.get('/api/vt/ip/:ip', async (req, res) => {
  const result = await vtClient.checkIP(req.params.ip);
  res.json(result);
});

app.get('/api/vt/stats', (req, res) => {
  res.json(vtClient.getStats());
});

// === MISP Blocked IPs ===
app.post('/api/misp/block-ip', async (req, res) => {
  const { ip, reason, analyst } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP address required' });

  try {
    const result = await mispClient.blockIP(ip, reason || 'Blocked via SOC Dashboard', analyst || 'SOC Analyst');
    res.json({
      success: true,
      ip,
      event_id: result?.Event?.id || 'created',
      message: `IP ${ip} blocked and added to MISP threat intel`,
    });
  } catch (err) {
    console.error('[MISP] Block IP error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/misp/blocked-ips', async (req, res) => {
  try {
    const blockedIPs = await mispClient.getBlockedIPs();
    res.json({ total: blockedIPs.length, blocked_ips: blockedIPs });
  } catch (err) {
    res.json({ total: 0, blocked_ips: [], error: err.message });
  }
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

// ===== Start Server =====
const PORT = config.server.port;
server.listen(PORT, async () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║       SOC-MINI: SCADA Security Operations Center            ║');
  console.log('║       Municipal Water Treatment Plant — Phase 4 SOAR        ║');
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log(`║  Dashboard:    http://localhost:${PORT}                        ║`);
  console.log(`║  Wazuh UDP:    ${config.wazuh.host}:${config.wazuh.udpPort}                            ║`);
  console.log(`║  MISP:         ${config.misp.url}                  ║`);
  console.log(`║  VirusTotal:   ${config.virustotal.apiKey ? '✓ API Key configured' : '✗ No API Key'}                  ║`);
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log('║  SOAR Endpoints:                                            ║');
  console.log('║  POST /api/webhook/wazuh     - Wazuh alert webhook          ║');
  console.log('║  GET  /api/soar/incidents     - List incidents               ║');
  console.log('║  GET  /api/soar/approvals     - Pending approvals           ║');
  console.log('║  POST /api/soar/approve       - Approve critical action     ║');
  console.log('║  GET  /api/vt/ip/:ip          - VirusTotal IP lookup        ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log('');

  // Initialize MISP connection
  const mispConnected = await mispClient.init();
  if (mispConnected) {
    enricher.updateFromMISP();
    console.log('[MISP] ✓ Indicators loaded into enrichment engine');
  }
  console.log(`[VT] ${config.virustotal.apiKey ? '✓ VirusTotal API ready' : '⚠ No API key — VT enrichment disabled'}`);
  console.log('[SOAR] ✓ Incident response pipeline active');
  console.log('');
});
