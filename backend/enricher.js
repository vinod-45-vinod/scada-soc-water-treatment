/**
 * Log Enrichment Engine
 * Enriches SCADA events with CTI, IoC, IoA, MITRE ATT&CK data
 */

const config = require('./config');
const { v4: uuidv4 } = require('uuid');

class LogEnricher {
  constructor(mispClient = null) {
    this.maliciousIPs = new Set(config.threatIntel.maliciousIPs);
    this.suspiciousIPs = new Set(config.threatIntel.suspiciousIPs);
    this.internalIPs = new Set(config.threatIntel.internalIPs);
    this.loginAttempts = new Map(); // Track login attempts per IP for brute-force detection
    this.mispClient = mispClient; // MISP integration
  }

  /**
   * Update malicious IPs from MISP
   */
  updateFromMISP() {
    if (this.mispClient && this.mispClient.connected) {
      const mispIPs = this.mispClient.getMaliciousIPs();
      // Merge MISP indicators with hardcoded ones
      for (const ip of mispIPs) {
        this.maliciousIPs.add(ip);
      }
      console.log(`[ENRICHER] Updated with ${mispIPs.length} MISP indicators. Total malicious IPs: ${this.maliciousIPs.size}`);
    }
  }

  /**
   * Main enrichment method - takes a raw event and returns enriched log
   */
  enrichEvent(event) {
    const enriched = {
      // Base event data
      event_id: uuidv4(),
      timestamp: new Date().toISOString(),
      event_type: event.event_type,
      description: event.description || '',
      source_ip: event.source_ip || '0.0.0.0',
      destination_ip: event.destination_ip || '10.0.1.10',
      username: event.username || 'unknown',
      status: event.status || 'INFO',
      plant_name: config.scada.plantName,

      // Sensor data (if applicable)
      sensor_type: event.sensor_type || null,
      sensor_value: event.sensor_value || null,
      sensor_unit: event.sensor_unit || null,
      sensor_status: event.sensor_status || null,

      // PLC data (if applicable)
      plc_id: event.plc_id || null,
      plc_command: event.plc_command || null,
      plc_zone: event.plc_zone || null,

      // Enrichment fields (will be populated below)
      ioc_type: 'NONE',
      ioa_type: 'NONE',
      attack_stage: 'NONE',
      mitre_id: 'N/A',
      mitre_technique: 'N/A',
      mitre_tactic: 'N/A',
      threat_severity: 'LOW',
      threat_intel_tag: 'CLEAN',
      is_malicious_ip: false,
      risk_score: 0,
    };

    // Apply enrichment layers
    this._enrichThreatIntel(enriched);
    this._enrichIoC(enriched);
    this._enrichIoA(enriched);
    this._enrichMITRE(enriched);
    this._enrichAttackStage(enriched);
    this._calculateRiskScore(enriched);

    return enriched;
  }

  /**
   * CTI Enrichment - Check IPs against threat intelligence feeds (hardcoded + MISP)
   */
  _enrichThreatIntel(log) {
    // Check MISP indicators first (if connected)
    const mispMatch = this.mispClient && this.mispClient.connected && this.mispClient.isIPMalicious(log.source_ip);

    if (this.maliciousIPs.has(log.source_ip) || mispMatch) {
      log.threat_intel_tag = 'THREAT_INTEL_MATCH';
      log.is_malicious_ip = true;
      log.threat_severity = this._elevate(log.threat_severity, 'CRITICAL');
      log.misp_match = mispMatch ? true : false;
    } else if (this.suspiciousIPs.has(log.source_ip)) {
      log.threat_intel_tag = 'SUSPICIOUS_IP';
      log.threat_severity = this._elevate(log.threat_severity, 'HIGH');
    } else if (!this.internalIPs.has(log.source_ip)) {
      log.threat_intel_tag = 'UNKNOWN_EXTERNAL';
      log.threat_severity = this._elevate(log.threat_severity, 'MEDIUM');
    }
  }

  /**
   * IoC Enrichment - Indicators of Compromise
   */
  _enrichIoC(log) {
    switch (log.event_type) {
      case 'SENSOR_ANOMALY':
        log.ioc_type = 'ANOMALOUS_SENSOR_DATA';
        log.threat_severity = this._elevate(log.threat_severity, 'HIGH');
        break;
      case 'MALWARE_DETECTED':
        log.ioc_type = 'MALWARE_SIGNATURE';
        log.threat_severity = this._elevate(log.threat_severity, 'CRITICAL');
        break;
      case 'LOGIN_ATTEMPT':
        if (log.status === 'FAILED') {
          log.ioc_type = 'FAILED_AUTH';
          log.threat_severity = this._elevate(log.threat_severity, 'MEDIUM');
        }
        break;
      case 'PLC_COMMAND':
        if (log.status === 'UNAUTHORIZED') {
          log.ioc_type = 'UNAUTHORIZED_ACCESS';
          log.threat_severity = this._elevate(log.threat_severity, 'CRITICAL');
        }
        break;
      case 'LATERAL_MOVEMENT':
        log.ioc_type = 'NETWORK_ANOMALY';
        log.threat_severity = this._elevate(log.threat_severity, 'HIGH');
        break;
    }

    // Check for suspicious IP as IoC
    if (log.is_malicious_ip) {
      log.ioc_type = log.ioc_type !== 'NONE' ? `${log.ioc_type}+MALICIOUS_IP` : 'MALICIOUS_IP';
    }
  }

  /**
   * IoA Enrichment - Indicators of Attack
   */
  _enrichIoA(log) {
    // Track login attempts for brute-force detection
    if (log.event_type === 'LOGIN_ATTEMPT' && log.status === 'FAILED') {
      const key = log.source_ip;
      const now = Date.now();
      if (!this.loginAttempts.has(key)) {
        this.loginAttempts.set(key, []);
      }
      const attempts = this.loginAttempts.get(key);
      attempts.push(now);
      // Keep only attempts in last 5 minutes
      const recentAttempts = attempts.filter(t => now - t < 300000);
      this.loginAttempts.set(key, recentAttempts);

      if (recentAttempts.length >= 3) {
        log.ioa_type = 'BRUTE_FORCE_BEHAVIOR';
        log.threat_severity = this._elevate(log.threat_severity, 'CRITICAL');
      } else {
        log.ioa_type = 'SUSPICIOUS_LOGIN';
      }
    }

    if (log.event_type === 'PLC_COMMAND' && log.status === 'UNAUTHORIZED') {
      log.ioa_type = 'UNAUTHORIZED_PLC_EXECUTION';
      log.threat_severity = this._elevate(log.threat_severity, 'CRITICAL');
    }

    if (log.event_type === 'SENSOR_ANOMALY') {
      log.ioa_type = 'SENSOR_MANIPULATION';
    }

    if (log.event_type === 'MALWARE_DETECTED') {
      log.ioa_type = 'MALWARE_EXECUTION';
    }

    if (log.event_type === 'LATERAL_MOVEMENT') {
      log.ioa_type = 'IT_OT_BOUNDARY_CROSSING';
    }
  }

  /**
   * MITRE ATT&CK Enrichment
   */
  _enrichMITRE(log) {
    let mitreKey = log.event_type;

    // Use more specific MITRE mapping based on context
    if (log.event_type === 'LOGIN_ATTEMPT' && log.status === 'FAILED') {
      // Failed logins = T1110 Brute Force (credential guessing)
      mitreKey = 'BRUTE_FORCE';
    }
    // Successful logins from suspicious/malicious IPs = T1078 Valid Accounts (compromised creds)
    // LOGIN_ATTEMPT + SUCCESS stays as LOGIN_ATTEMPT → T1078

    if (log.event_type === 'PLC_COMMAND' && log.status === 'UNAUTHORIZED') {
      mitreKey = 'UNAUTHORIZED_PLC';
    }

    const mapping = config.mitre[mitreKey];
    if (mapping) {
      log.mitre_id = mapping.id;
      log.mitre_technique = mapping.technique;
      log.mitre_tactic = mapping.tactic;
    }
  }

  /**
   * Attack Stage Enrichment (Kill Chain)
   */
  _enrichAttackStage(log) {
    switch (log.event_type) {
      case 'LOGIN_ATTEMPT':
        log.attack_stage = log.status === 'FAILED' ? 'Initial Access' : 'Execution';
        break;
      case 'PLC_COMMAND':
        log.attack_stage = log.status === 'UNAUTHORIZED' ? 'Execution' : 'Collection';
        break;
      case 'SENSOR_ANOMALY':
        log.attack_stage = 'Impact';
        break;
      case 'MALWARE_DETECTED':
        log.attack_stage = 'Persistence';
        break;
      case 'LATERAL_MOVEMENT':
        log.attack_stage = 'Lateral Movement';
        break;
      default:
        log.attack_stage = 'Reconnaissance';
    }
  }

  /**
   * Calculate composite risk score (0-100)
   */
  _calculateRiskScore(log) {
    let score = 0;

    // Severity weight
    const sevWeights = { LOW: 10, MEDIUM: 30, HIGH: 60, CRITICAL: 90 };
    score += sevWeights[log.threat_severity] || 0;

    // CTI bonus
    if (log.threat_intel_tag === 'THREAT_INTEL_MATCH') score += 10;

    // IoC bonus
    if (log.ioc_type !== 'NONE') score += 5;

    // IoA bonus
    if (log.ioa_type !== 'NONE') score += 5;

    log.risk_score = Math.min(score, 100);
  }

  /**
   * Format enriched log as plain-text syslog message for Wazuh UDP
   */
  formatForWazuh(enrichedLog) {
    const parts = [
      `event_type=${enrichedLog.event_type}`,
      `"${enrichedLog.description}"`,
      `source_ip=${enrichedLog.source_ip}`,
      `destination_ip=${enrichedLog.destination_ip}`,
      `username=${enrichedLog.username}`,
      `status=${enrichedLog.status}`,
      `ioc_type=${enrichedLog.ioc_type}`,
      `ioa_type=${enrichedLog.ioa_type}`,
      `attack_stage=${enrichedLog.attack_stage}`,
      `mitre_id=${enrichedLog.mitre_id}`,
      `mitre_technique=${enrichedLog.mitre_technique}`,
      `threat_severity=${enrichedLog.threat_severity}`,
      `threat_intel_tag=${enrichedLog.threat_intel_tag}`,
      `risk_score=${enrichedLog.risk_score}`,
    ];

    if (enrichedLog.plc_id) {
      parts.push(`plc_id=${enrichedLog.plc_id}`);
      parts.push(`plc_command=${enrichedLog.plc_command}`);
    }

    if (enrichedLog.sensor_type) {
      parts.push(`sensor_type=${enrichedLog.sensor_type}`);
      parts.push(`sensor_value=${enrichedLog.sensor_value}`);
    }

    return `SCADA_SOC: ${parts.join(' ')}`;
  }

  /**
   * Severity elevation - only goes up, never down
   */
  _elevate(current, proposed) {
    const levels = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
    return levels[proposed] > levels[current] ? proposed : current;
  }

  /**
   * Get brute force stats for an IP
   */
  getBruteForceStats(ip) {
    const attempts = this.loginAttempts.get(ip) || [];
    const now = Date.now();
    const recent = attempts.filter(t => now - t < 300000);
    return {
      ip,
      totalAttempts: recent.length,
      isBruteForce: recent.length >= 3,
      windowMinutes: 5,
    };
  }
}

module.exports = LogEnricher;
