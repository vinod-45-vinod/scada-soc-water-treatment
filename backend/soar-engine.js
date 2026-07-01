/**
 * SOAR (Security Orchestration, Automation & Response) Engine
 * Implements the incident response automation pipeline:
 *   Alert Trigger → Enrichment → Decision → Response → Report
 */

const config = require('./config');
const fs = require('fs');
const path = require('path');
const https = require('https');

class SOAREngine {
  constructor(vtClient, mispClient) {
    this.vtClient = vtClient;
    this.mispClient = mispClient;
    this.incidents = [];
    this.pendingApprovals = new Map();
    this.responseLog = [];
    this.stats = {
      totalIncidents: 0,
      criticalIncidents: 0,
      highIncidents: 0,
      mediumIncidents: 0,
      blockedIPs: [],
      terminatedSessions: [],
      avgMTTD: 0,
      avgMTTR: 0,
    };
    this.blockedIPs = new Set();
    this.failedLoginAttempts = new Map(); // Track failed logins per IP: ip -> {count, firstSeen, lastSeen}
    this.autoBlockThreshold = 3; // Block after 3 failed login attempts

    // Ensure reports directory
    const reportsDir = path.join(__dirname, '..', 'logs', 'reports');
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }
  }

  // ========================================
  // STEP 1: ALERT TRIGGER
  // ========================================

  /**
   * Process incoming alert (from Wazuh webhook or internal events)
   * Only triggers for: unauthorized PLC, malware, brute force, CTI match
   */
  async processAlert(alert) {
    const triggerTypes = [
      'PLC_COMMAND',
      'MALWARE_DETECTED',
      'LOGIN_ATTEMPT',
      'LATERAL_MOVEMENT',
    ];

    const triggerConditions = [
      alert.threat_intel_tag === 'THREAT_INTEL_MATCH',
      alert.ioa_type === 'BRUTE_FORCE_BEHAVIOR',
      alert.status === 'UNAUTHORIZED',
      alert.event_type === 'MALWARE_DETECTED',
      alert.ioa_type === 'UNAUTHORIZED_PLC_EXECUTION',
      alert.threat_severity === 'CRITICAL',
    ];

    // Only trigger for relevant alert types
    if (!triggerTypes.includes(alert.event_type) && !triggerConditions.some(c => c)) {
      return null;
    }

    console.log(`\n[SOAR] ⚡ Alert triggered: ${alert.event_type} from ${alert.source_ip}`);
    const detectionTime = new Date();

    // Create incident
    const incident = {
      id: `INC-${Date.now()}`,
      created_at: detectionTime.toISOString(),
      status: 'OPEN',
      alert_source: alert,
      source_ip: alert.source_ip,
      event_type: alert.event_type,
      description: alert.description,

      // Will be populated during enrichment
      enrichment: {},
      classification: null,
      severity: null,
      response_actions: [],
      requires_approval: false,
      approval_status: null,
      timeline: [],
      report: null,

      // Metrics
      mttd: 0, // Mean Time to Detect (seconds)
      mttr: 0, // Mean Time to Respond (seconds)
    };

    incident.timeline.push({
      time: detectionTime.toISOString(),
      action: 'ALERT_RECEIVED',
      details: `Alert received: ${alert.event_type} - ${alert.description}`,
    });

    // STEP 2: Enrichment
    await this._enrichAlert(incident);

    // STEP 3: Decision Logic
    this._classifyIncident(incident);

    // STEP 4: Automated Response
    await this._executeResponse(incident);

    // STEP 5: AUTO-BLOCK brute force attacker IPs in MISP
    await this._autoBlockBruteForce(incident);

    // Calculate MTTD (time from event to detection)
    incident.mttd = Math.round((Date.now() - detectionTime.getTime()) / 1000);

    // Store incident
    this.incidents.push(incident);
    this.stats.totalIncidents++;

    if (incident.severity === 'CRITICAL') this.stats.criticalIncidents++;
    else if (incident.severity === 'HIGH') this.stats.highIncidents++;
    else this.stats.mediumIncidents++;

    console.log(`[SOAR] ✓ Incident ${incident.id} created — Severity: ${incident.severity}`);

    // Forward alert to Shuffle SOAR (cloud) webhook
    this._forwardToShuffle(alert, incident);

    return incident;
  }

  /**
   * Forward alert to Shuffle cloud via Execute API
   * Uses /api/v1/workflows/{id}/execute instead of webhook (no manual start needed)
   * Rate-limited to 1 request per 10 seconds to avoid HTTP 429
   */
  _forwardToShuffle(alert, incident) {
    if (!config.shuffle?.enabled || !config.shuffle?.workflowId || !config.shuffle?.apiKey) return;

    // Rate limiting: max 1 request per 10 seconds
    const now = Date.now();
    if (this._lastShuffleForward && (now - this._lastShuffleForward) < 10000) {
      console.log(`[SHUFFLE] ⏳ Rate-limited (waiting ${Math.ceil((10000 - (now - this._lastShuffleForward))/1000)}s)`);
      return;
    }
    this._lastShuffleForward = now;

    try {
      const payload = JSON.stringify({
        execution_argument: JSON.stringify({
          source_ip: alert.source_ip,
          event_type: alert.event_type,
          description: alert.description,
          threat_severity: alert.threat_severity || incident.severity,
          threat_intel_tag: alert.threat_intel_tag,
          mitre_id: alert.mitre_id,
          mitre_technique: alert.mitre_technique,
          username: alert.username,
          status: alert.status,
          incident_id: incident.id,
          classification: incident.classification,
          risk_score: alert.risk_score,
          ioc_type: alert.ioc_type,
          ioa_type: alert.ioa_type,
          timestamp: new Date().toISOString(),
        }),
        start: '',
      });

      const options = {
        hostname: 'shuffler.io',
        port: 443,
        path: `/api/v1/workflows/${config.shuffle.workflowId}/execute`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          'Authorization': 'Bearer ' + config.shuffle.apiKey,
        },
      };

      const req = https.request(options, res => {
        let d = '';
        res.on('data', c => d += c);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const result = JSON.parse(d);
              console.log(`[SHUFFLE] ✓ Workflow executed (HTTP ${res.statusCode}) — Execution: ${result.execution_id?.slice(0, 8) || 'ok'}`);
            } catch {
              console.log(`[SHUFFLE] ✓ Workflow executed (HTTP ${res.statusCode})`);
            }
          } else {
            console.log(`[SHUFFLE] ⚠ Shuffle responded HTTP ${res.statusCode}: ${d.slice(0, 100)}`);
          }
        });
      });
      req.on('error', e => console.error(`[SHUFFLE] Execute error: ${e.message}`));
      req.write(payload);
      req.end();
    } catch (err) {
      console.error(`[SHUFFLE] Execute failed: ${err.message}`);
    }
  }

  // ========================================
  // STEP 2: AUTOMATED ENRICHMENT
  // ========================================

  async _enrichAlert(incident) {
    const alert = incident.alert_source;
    console.log(`[SOAR] 🔍 Enriching alert from ${alert.source_ip}...`);

    incident.timeline.push({
      time: new Date().toISOString(),
      action: 'ENRICHMENT_STARTED',
      details: 'Querying VirusTotal, MISP, and internal CTI',
    });

    // VirusTotal IP reputation
    let vtResult = { status: 'skipped', malicious: false };
    if (this.vtClient) {
      vtResult = await this.vtClient.checkIP(alert.source_ip);
    }

    // MISP threat intelligence
    let mispResult = { found: false };
    if (this.mispClient && this.mispClient.connected) {
      mispResult = await this.mispClient.searchIndicator(alert.source_ip);
    }

    incident.enrichment = {
      virustotal: {
        ip: alert.source_ip,
        malicious: vtResult.malicious || false,
        suspicious: vtResult.suspicious || false,
        reputation: vtResult.reputation || 0,
        malicious_count: vtResult.malicious_count || 0,
        total_engines: vtResult.total_engines || 0,
        country: vtResult.country || 'Unknown',
        as_owner: vtResult.as_owner || 'Unknown',
        vt_link: vtResult.vt_link || '',
        status: vtResult.status,
      },
      misp: {
        found: mispResult.found || false,
        matches: mispResult.matches || [],
        match_count: (mispResult.matches || []).length,
        is_blocked: (mispResult.matches || []).some(m =>
          (m.to_ids === true || m.to_ids === 'true') &&
          (m.comment || '').toLowerCase().includes('blocked')
        ),
        indicator: alert.source_ip,
      },
      internal_cti: {
        threat_intel_tag: alert.threat_intel_tag,
        is_malicious_ip: alert.is_malicious_ip,
        ioc_type: alert.ioc_type,
        ioa_type: alert.ioa_type,
        mitre_id: alert.mitre_id,
        mitre_technique: alert.mitre_technique,
        mitre_tactic: alert.mitre_tactic,
        attack_stage: alert.attack_stage,
        risk_score: alert.risk_score,
      },
      recent_activity: {
        event_type: alert.event_type,
        status: alert.status,
        username: alert.username,
        plc_id: alert.plc_id,
        plc_command: alert.plc_command,
        sensor_type: alert.sensor_type,
        sensor_value: alert.sensor_value,
      },
    };

    incident.timeline.push({
      time: new Date().toISOString(),
      action: 'ENRICHMENT_COMPLETED',
      details: `VT: ${vtResult.malicious ? 'MALICIOUS' : 'CLEAN'} | MISP: ${mispResult.found ? 'FOUND' : 'NOT_FOUND'} | CTI: ${alert.threat_intel_tag}`,
    });

    console.log(`[SOAR]   VT: ${vtResult.malicious ? '🔴 MALICIOUS' : '🟢 CLEAN'} | MISP: ${mispResult.found ? '🔴 FOUND' : '⚪ NOT FOUND'} | CTI: ${alert.threat_intel_tag}`);
  }

  // ========================================
  // STEP 3: DECISION LOGIC
  // ========================================

  _classifyIncident(incident) {
    const alert = incident.alert_source;
    const enrichment = incident.enrichment;

    let severity = 'MEDIUM';
    let classification = 'GENERAL_ALERT';

    // CRITICAL: CTI match + unusual IP + PLC command
    if (
      alert.threat_intel_tag === 'THREAT_INTEL_MATCH' &&
      !['10.0.1.10', '10.0.1.20', '10.0.1.30', '10.0.1.50'].includes(alert.source_ip) &&
      (alert.event_type === 'PLC_COMMAND' || alert.ioa_type === 'UNAUTHORIZED_PLC_EXECUTION')
    ) {
      severity = 'CRITICAL';
      classification = 'PLC_COMMAND_INJECTION_APT';
    }
    // CRITICAL: Malware on SCADA
    else if (alert.event_type === 'MALWARE_DETECTED') {
      severity = 'CRITICAL';
      classification = 'ICS_MALWARE_DETECTED';
    }
    // CRITICAL: CTI match + brute force
    else if (
      alert.threat_intel_tag === 'THREAT_INTEL_MATCH' &&
      alert.ioa_type === 'BRUTE_FORCE_BEHAVIOR'
    ) {
      severity = 'CRITICAL';
      classification = 'BRUTE_FORCE_FROM_KNOWN_THREAT_ACTOR';
    }
    // CRITICAL: VT says malicious + PLC access
    else if (
      enrichment.virustotal.malicious &&
      alert.event_type === 'PLC_COMMAND'
    ) {
      severity = 'CRITICAL';
      classification = 'MALICIOUS_IP_PLC_ACCESS';
    }
    // HIGH: CTI match (any event type)
    else if (alert.threat_intel_tag === 'THREAT_INTEL_MATCH') {
      severity = 'HIGH';
      classification = 'THREAT_INTEL_MATCH_ACTIVITY';
    }
    // HIGH: Brute force without CTI
    else if (alert.ioa_type === 'BRUTE_FORCE_BEHAVIOR') {
      severity = 'HIGH';
      classification = 'BRUTE_FORCE_ATTACK';
    }
    // HIGH: Lateral movement
    else if (alert.event_type === 'LATERAL_MOVEMENT') {
      severity = 'HIGH';
      classification = 'IT_OT_LATERAL_MOVEMENT';
    }
    // HIGH: Unauthorized PLC
    else if (alert.status === 'UNAUTHORIZED') {
      severity = 'HIGH';
      classification = 'UNAUTHORIZED_PLC_COMMAND';
    }

    // Requires human approval for CRITICAL SCADA actions
    incident.requires_approval = severity === 'CRITICAL';
    incident.severity = severity;
    incident.classification = classification;

    incident.timeline.push({
      time: new Date().toISOString(),
      action: 'CLASSIFICATION_COMPLETED',
      details: `Severity: ${severity} | Classification: ${classification} | Approval Required: ${incident.requires_approval}`,
    });

    console.log(`[SOAR] ⚖️ Classification: ${severity} — ${classification}`);
  }

  // ========================================
  // STEP 4: AUTOMATED RESPONSE
  // ========================================

  async _executeResponse(incident) {
    const alert = incident.alert_source;
    console.log(`[SOAR] 🛡️ Executing response for ${incident.severity} incident...`);

    incident.timeline.push({
      time: new Date().toISOString(),
      action: 'RESPONSE_STARTED',
      details: `Executing automated response for ${incident.severity} incident`,
    });

    // For all severities: log collection
    incident.response_actions.push({
      action: 'LOG_COLLECTION',
      status: 'COMPLETED',
      time: new Date().toISOString(),
      details: `Evidence logs collected for ${alert.source_ip}`,
    });

    if (incident.severity === 'CRITICAL' || incident.severity === 'HIGH') {
      // Block attacker IP (simulated firewall API call)
      const blockResult = this._simulateBlockIP(alert.source_ip);
      incident.response_actions.push(blockResult);

      // Terminate VPN session (simulated)
      const vpnResult = this._simulateTerminateVPN(alert.source_ip, alert.username);
      incident.response_actions.push(vpnResult);

      // Create incident ticket
      const ticketResult = this._createTicket(incident);
      incident.response_actions.push(ticketResult);

      // Send alert notifications
      const notifyResult = this._sendNotifications(incident);
      incident.response_actions.push(notifyResult);
    }

    if (incident.severity === 'CRITICAL') {
      // STEP 5: Queue for human approval
      this.pendingApprovals.set(incident.id, {
        incident_id: incident.id,
        classification: incident.classification,
        actions_pending: [
          { action: 'ISOLATE_PLC', description: `Isolate PLC ${alert.plc_id || 'N/A'} from network`, status: 'PENDING_APPROVAL' },
          { action: 'REVOKE_CREDENTIALS', description: `Revoke credentials for user: ${alert.username}`, status: 'PENDING_APPROVAL' },
          { action: 'LOCK_SCADA_SERVER', description: 'Lock SCADA HMI server access', status: 'PENDING_APPROVAL' },
        ],
        created_at: new Date().toISOString(),
      });

      incident.approval_status = 'PENDING';
      incident.response_actions.push({
        action: 'HUMAN_APPROVAL_REQUIRED',
        status: 'PENDING',
        time: new Date().toISOString(),
        details: 'Critical actions queued for analyst approval: Isolate PLC, Revoke Credentials, Lock SCADA Server',
      });

      console.log(`[SOAR] ⏳ Human approval required for critical actions (Incident: ${incident.id})`);
    }

    // Calculate MTTR
    incident.mttr = Math.round((Date.now() - new Date(incident.created_at).getTime()) / 1000);

    // STEP 6: Generate incident report
    const report = this._generateReport(incident);
    incident.report = report;

    // Update MISP with new IOCs
    if (this.mispClient && this.mispClient.connected && incident.severity === 'CRITICAL') {
      try {
        await this.mispClient.createEvent(alert);
        incident.response_actions.push({
          action: 'MISP_UPDATED',
          status: 'COMPLETED',
          time: new Date().toISOString(),
          details: 'IOC pushed to MISP threat intelligence platform',
        });
      } catch (err) {
        console.error('[SOAR] MISP update failed:', err.message);
      }
    }

    incident.timeline.push({
      time: new Date().toISOString(),
      action: 'RESPONSE_COMPLETED',
      details: `${incident.response_actions.length} response actions executed. MTTR: ${incident.mttr}s`,
    });

    // Store in response log
    this.responseLog.push({
      incident_id: incident.id,
      severity: incident.severity,
      classification: incident.classification,
      response_actions: incident.response_actions.map(a => a.action),
      mttr: incident.mttr,
      time: new Date().toISOString(),
    });

    // Update stats
    this._updateStats(incident);
  }

  // ========================================
  // STEP 5: AUTO-BLOCK BRUTE FORCE IPs IN MISP
  // ========================================

  async _autoBlockBruteForce(incident) {
    const alert = incident.alert_source;
    const ip = alert.source_ip;

    // Only auto-block for brute force related classifications
    const bruteForceClassifications = [
      'BRUTE_FORCE_ATTACK',
      'BRUTE_FORCE_FROM_KNOWN_THREAT_ACTOR',
      'GENERAL_ALERT',                      // LOGIN_ATTEMPT events
    ];

    const isBruteForce = bruteForceClassifications.includes(incident.classification) &&
      (alert.event_type === 'LOGIN_ATTEMPT' || alert.ioa_type === 'BRUTE_FORCE_BEHAVIOR');

    if (!isBruteForce) return;

    // Skip internal/private IPs
    if (ip.startsWith('10.0.1.') || ip === '127.0.0.1' || ip === '0.0.0.0') return;

    // Track failed login attempts per IP
    const now = Date.now();
    const tracker = this.failedLoginAttempts.get(ip) || { count: 0, firstSeen: now, lastSeen: now };
    tracker.count++;
    tracker.lastSeen = now;
    this.failedLoginAttempts.set(ip, tracker);

    console.log(`[SOAR] 🔢 Failed login attempt #${tracker.count}/${this.autoBlockThreshold} from ${ip}`);

    // Only auto-block after threshold is reached
    if (tracker.count < this.autoBlockThreshold) {
      incident.timeline.push({
        time: new Date().toISOString(),
        action: 'AUTO_BLOCK_PENDING',
        details: `Failed attempt #${tracker.count}/${this.autoBlockThreshold} from ${ip} — ${this.autoBlockThreshold - tracker.count} more before auto-block`,
      });
      return;
    }

    // Skip if MISP not connected
    if (!this.mispClient || !this.mispClient.connected) {
      console.log(`[SOAR] ⚠ MISP not connected — skipping auto-block for ${ip}`);
      return;
    }

    try {
      // Check if already blocked
      const existing = await this.mispClient.searchIndicator(ip);
      const alreadyBlocked = (existing.matches || []).some(m =>
        (m.to_ids === true || m.to_ids === 'true') &&
        (m.comment || '').toLowerCase().includes('blocked')
      );

      if (alreadyBlocked) {
        console.log(`[SOAR] 🚫 IP ${ip} already blocked in MISP — skipping`);
        incident.timeline.push({
          time: new Date().toISOString(),
          action: 'AUTO_BLOCK_SKIPPED',
          details: `IP ${ip} already blocked in MISP`,
        });
        return;
      }

      // Auto-block the IP in MISP
      const result = await this.mispClient.blockIP(
        ip,
        `Auto-blocked by SOAR: ${incident.classification} — ${alert.description || 'Brute force detected'}`,
        'SOAR Auto-Response'
      );

      incident.response_actions.push({
        action: 'MISP_AUTO_BLOCK',
        status: 'COMPLETED',
        time: new Date().toISOString(),
        details: `IP ${ip} auto-blocked in MISP (Event #${result?.Event?.id || 'created'})`,
      });

      incident.timeline.push({
        time: new Date().toISOString(),
        action: 'AUTO_BLOCK_COMPLETED',
        details: `🚫 IP ${ip} auto-blocked in MISP — Event #${result?.Event?.id || 'created'}`,
      });

      console.log(`[SOAR] 🚫 AUTO-BLOCKED: ${ip} in MISP (Event #${result?.Event?.id || 'created'}) — ${incident.classification}`);

    } catch (err) {
      console.error(`[SOAR] Auto-block failed for ${ip}:`, err.message);
      incident.timeline.push({
        time: new Date().toISOString(),
        action: 'AUTO_BLOCK_FAILED',
        details: `Failed to auto-block ${ip}: ${err.message}`,
      });
    }
  }

  // ========================================
  // SIMULATED RESPONSE ACTIONS
  // ========================================

  _simulateBlockIP(ip) {
    this.blockedIPs.add(ip);
    this.stats.blockedIPs.push({ ip, time: new Date().toISOString() });
    console.log(`[SOAR] 🚫 Blocked IP: ${ip} (firewall rule applied)`);
    return {
      action: 'BLOCK_IP',
      status: 'COMPLETED',
      time: new Date().toISOString(),
      details: `Firewall rule created: DENY ALL from ${ip} to OT_NETWORK (10.0.1.0/24)`,
      api_response: { rule_id: `FW-${Date.now()}`, ip, direction: 'inbound', action: 'DENY' },
    };
  }

  _simulateTerminateVPN(ip, username) {
    this.stats.terminatedSessions.push({ ip, username, time: new Date().toISOString() });
    console.log(`[SOAR] 🔌 VPN session terminated: ${username}@${ip}`);
    return {
      action: 'TERMINATE_VPN',
      status: 'COMPLETED',
      time: new Date().toISOString(),
      details: `VPN session terminated for ${username} from ${ip}. Session token revoked.`,
      api_response: { session_id: `VPN-${Date.now()}`, username, ip, status: 'terminated' },
    };
  }

  _createTicket(incident) {
    const ticketId = `TKT-${Date.now()}`;
    console.log(`[SOAR] 🎫 Ticket created: ${ticketId}`);
    return {
      action: 'CREATE_TICKET',
      status: 'COMPLETED',
      time: new Date().toISOString(),
      details: `Incident ticket ${ticketId} created for: ${incident.classification}`,
      ticket: {
        id: ticketId,
        title: `[${incident.severity}] ${incident.classification} — ${incident.alert_source.source_ip}`,
        priority: incident.severity,
        assignee: 'SOC_ANALYST_L2',
        status: 'OPEN',
      },
    };
  }

  _sendNotifications(incident) {
    console.log(`[SOAR] 📧 Notifications sent: Email + SMS`);
    return {
      action: 'SEND_NOTIFICATIONS',
      status: 'COMPLETED',
      time: new Date().toISOString(),
      details: 'Alert sent via Email and SMS to SOC team, Plant Manager, and CISO',
      notifications: [
        { channel: 'EMAIL', recipient: 'soc-team@waterplant.local', status: 'SENT' },
        { channel: 'EMAIL', recipient: 'plant-manager@waterplant.local', status: 'SENT' },
        { channel: 'SMS', recipient: '+1-555-SOC-TEAM', status: 'SENT' },
        { channel: 'SMS', recipient: '+1-555-MANAGER', status: 'SENT' },
      ],
    };
  }

  // ========================================
  // STEP 5: HUMAN APPROVAL
  // ========================================

  approveAction(incidentId, actionName, analystName = 'SOC_Analyst') {
    const approval = this.pendingApprovals.get(incidentId);
    if (!approval) return { error: 'No pending approval found' };

    const action = approval.actions_pending.find(a => a.action === actionName);
    if (!action) return { error: `Action ${actionName} not found` };

    action.status = 'APPROVED';
    action.approved_by = analystName;
    action.approved_at = new Date().toISOString();

    // Execute the approved action
    let result = {};
    switch (actionName) {
      case 'ISOLATE_PLC':
        result = { action: 'ISOLATE_PLC', status: 'COMPLETED', details: `PLC isolated from network by ${analystName}` };
        console.log(`[SOAR] ✅ PLC isolation APPROVED and executed by ${analystName}`);
        break;
      case 'REVOKE_CREDENTIALS':
        result = { action: 'REVOKE_CREDENTIALS', status: 'COMPLETED', details: `Credentials revoked by ${analystName}` };
        console.log(`[SOAR] ✅ Credential revocation APPROVED and executed by ${analystName}`);
        break;
      case 'LOCK_SCADA_SERVER':
        result = { action: 'LOCK_SCADA_SERVER', status: 'COMPLETED', details: `SCADA server locked by ${analystName}` };
        console.log(`[SOAR] ✅ SCADA server lock APPROVED and executed by ${analystName}`);
        break;
    }

    // Update incident
    const incident = this.incidents.find(i => i.id === incidentId);
    if (incident) {
      incident.response_actions.push({ ...result, time: new Date().toISOString() });
      incident.timeline.push({
        time: new Date().toISOString(),
        action: `${actionName}_APPROVED`,
        details: `Action approved by analyst: ${analystName}`,
      });

      // Check if all actions approved
      if (approval.actions_pending.every(a => a.status === 'APPROVED')) {
        incident.approval_status = 'ALL_APPROVED';
        incident.status = 'RESOLVED';
        incident.resolved_at = new Date().toISOString();
        incident.mttr = Math.round((Date.now() - new Date(incident.created_at).getTime()) / 1000);
        this.pendingApprovals.delete(incidentId);
        console.log(`[SOAR] 🏁 All actions approved — Incident ${incidentId} RESOLVED (MTTR: ${incident.mttr}s)`);
      }
    }

    return { status: 'approved', action: actionName, incident_id: incidentId, result };
  }

  denyAction(incidentId, actionName, analystName = 'SOC_Analyst', reason = '') {
    const approval = this.pendingApprovals.get(incidentId);
    if (!approval) return { error: 'No pending approval found' };

    const action = approval.actions_pending.find(a => a.action === actionName);
    if (!action) return { error: `Action ${actionName} not found` };

    action.status = 'DENIED';
    action.denied_by = analystName;
    action.denied_at = new Date().toISOString();
    action.reason = reason;

    console.log(`[SOAR] ❌ Action ${actionName} DENIED by ${analystName}: ${reason}`);
    return { status: 'denied', action: actionName, reason };
  }

  // ========================================
  // STEP 6: INCIDENT REPORT GENERATION
  // ========================================

  _generateReport(incident) {
    const report = {
      report_id: `RPT-${Date.now()}`,
      generated_at: new Date().toISOString(),
      incident_id: incident.id,
      severity: incident.severity,
      classification: incident.classification,
      status: incident.status,

      summary: {
        title: `${incident.severity} Security Incident: ${incident.classification}`,
        description: incident.alert_source.description,
        source_ip: incident.source_ip,
        event_type: incident.event_type,
        detected_at: incident.created_at,
        mttd_seconds: incident.mttd,
        mttr_seconds: incident.mttr,
      },

      enrichment_results: {
        virustotal: incident.enrichment.virustotal,
        misp: incident.enrichment.misp,
        internal_cti: incident.enrichment.internal_cti,
      },

      mitre_attack: {
        technique_id: incident.alert_source.mitre_id,
        technique_name: incident.alert_source.mitre_technique,
        tactic: incident.alert_source.mitre_tactic,
      },

      response_actions: incident.response_actions,
      timeline: incident.timeline,

      recommendations: this._getRecommendations(incident),
    };

    // Save report to file
    try {
      const reportPath = path.join(__dirname, '..', 'logs', 'reports', `${report.report_id}.json`);
      fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
      console.log(`[SOAR] 📋 Report saved: ${reportPath}`);
    } catch (err) {
      console.error('[SOAR] Report save error:', err.message);
    }

    return report;
  }

  _getRecommendations(incident) {
    const recs = [];
    switch (incident.classification) {
      case 'PLC_COMMAND_INJECTION_APT':
        recs.push('1. Immediately isolate affected PLC from the network');
        recs.push('2. Verify PLC firmware integrity against known-good baseline');
        recs.push('3. Review all Modbus/TCP traffic logs for additional unauthorized commands');
        recs.push('4. Reset all VPN credentials and enforce MFA');
        recs.push('5. Engage ICS-CERT for APT investigation');
        break;
      case 'BRUTE_FORCE_FROM_KNOWN_THREAT_ACTOR':
        recs.push('1. Block source IP at perimeter firewall');
        recs.push('2. Force password reset for targeted accounts');
        recs.push('3. Enable account lockout after 3 failed attempts');
        recs.push('4. Review VPN access logs for successful compromises');
        recs.push('5. Implement geo-blocking for non-operational regions');
        break;
      case 'ICS_MALWARE_DETECTED':
        recs.push('1. Isolate infected system immediately');
        recs.push('2. Capture forensic disk image before remediation');
        recs.push('3. Run full IOC sweep on all OT systems');
        recs.push('4. Check PLC logic integrity');
        recs.push('5. Report to ICS-CERT and law enforcement');
        break;
      default:
        recs.push('1. Monitor source IP for additional suspicious activity');
        recs.push('2. Review access logs for anomalies');
        recs.push('3. Update threat intelligence with new IOCs');
    }
    return recs;
  }

  _updateStats(incident) {
    const mttrValues = this.incidents.filter(i => i.mttr > 0).map(i => i.mttr);
    const mttdValues = this.incidents.filter(i => i.mttd > 0).map(i => i.mttd);
    this.stats.avgMTTR = mttrValues.length > 0 ? Math.round(mttrValues.reduce((a, b) => a + b, 0) / mttrValues.length) : 0;
    this.stats.avgMTTD = mttdValues.length > 0 ? Math.round(mttdValues.reduce((a, b) => a + b, 0) / mttdValues.length) : 0;
  }

  // ========================================
  // GETTERS
  // ========================================

  getIncidents() { return this.incidents; }
  getIncident(id) { return this.incidents.find(i => i.id === id); }
  getPendingApprovals() { return [...this.pendingApprovals.values()]; }
  getStats() { return { ...this.stats, totalPendingApprovals: this.pendingApprovals.size }; }
  getResponseLog() { return this.responseLog; }
  isIPBlocked(ip) { return this.blockedIPs.has(ip); }
}

module.exports = SOAREngine;
