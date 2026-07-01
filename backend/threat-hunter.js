/**
 * Threat Hunter Module
 * Proactive threat hunting capabilities for the SOC
 * 
 * Implements 3 Formal Threat Hunting Hypotheses:
 * H1: Unauthorized Modbus/TCP Communication to PLCs (Unknown IP → PLC)
 * H2: Brute-Force Attack Pattern (Failed Logins → Successful Login)
 * H3: Malware on Operator Workstation Connected to SCADA (EDR/Malware → PLC Access)
 * 
 * Plus 3 additional supporting hunts for comprehensive coverage.
 */

const config = require('./config');

class ThreatHunter {
  constructor() {
    this.eventBuffer = [];
    this.maxBufferSize = 1000;
    this.huntResults = [];
  }

  /**
   * Add event to the hunting buffer
   */
  addEvent(enrichedLog) {
    this.eventBuffer.push({
      ...enrichedLog,
      _indexed_at: Date.now(),
    });

    // Trim buffer
    if (this.eventBuffer.length > this.maxBufferSize) {
      this.eventBuffer = this.eventBuffer.slice(-this.maxBufferSize);
    }
  }

  /**
   * Run all threat hunts and return findings
   */
  runAllHunts() {
    const results = [];

    // === PRIMARY HYPOTHESES (H1, H2, H3) ===
    results.push(this.huntHypothesis1_UnauthorizedPLCComm());
    results.push(this.huntHypothesis2_BruteForcePattern());
    results.push(this.huntHypothesis3_MalwareOnWorkstation());

    // === SUPPORTING HUNTS ===
    results.push(this.huntSensorAnomalies());
    results.push(this.huntLateralMovement());
    results.push(this.huntThreatIntelMatches());

    this.huntResults = results.filter(r => r.findings.length > 0);
    return this.huntResults;
  }

  // ================================================================
  // HYPOTHESIS 1: Unauthorized Modbus/TCP Communication to PLCs
  // ================================================================
  // Hunting Hypothesis:
  //   If Modbus/TCP communication is observed from unknown IP addresses
  //   to PLC controllers, it may indicate unauthorized command injection.
  // Data Sources: Firewall Logs, Network Device Logs
  // Why Suspicious: Only authorized SCADA systems should communicate
  //   with PLCs. Any external communication is abnormal.
  // Expected Outcome: Identify rogue devices or attackers attempting
  //   to manipulate industrial processes
  // ================================================================
  huntHypothesis1_UnauthorizedPLCComm() {
    // Find all PLC commands from unauthorized/unknown sources or external IPs
    const plcEvents = this.eventBuffer.filter(
      e => e.event_type === 'PLC_COMMAND'
    );

    const internalIPs = new Set(config.threatIntel.internalIPs);
    const maliciousIPs = new Set(config.threatIntel.maliciousIPs);

    const findings = [];

    // Check 1: PLC commands from external/unknown IPs (non-internal)
    const externalPLCCommands = plcEvents.filter(
      e => !internalIPs.has(e.source_ip) || maliciousIPs.has(e.source_ip)
    );

    // Check 2: PLC commands marked as UNAUTHORIZED
    const unauthorizedPLCCommands = plcEvents.filter(
      e => e.status === 'UNAUTHORIZED'
    );

    // Check 3: Dangerous PLC commands (setpoint/safety modifications)
    const dangerousCommands = plcEvents.filter(
      e => ['MODIFY_SETPOINT', 'MODIFY_SAFETY_LOGIC', 'INJECT_PAYLOAD', 'OVERRIDE_PRESSURE'].includes(e.plc_command)
    );

    if (externalPLCCommands.length > 0) {
      const rogueIPs = [...new Set(externalPLCCommands.map(e => e.source_ip))];
      const targetedPLCs = [...new Set(externalPLCCommands.map(e => e.plc_id).filter(Boolean))];
      findings.push({
        type: 'UNAUTHORIZED_MODBUS_TCP_COMMUNICATION',
        severity: 'CRITICAL',
        description: 'Modbus/TCP communication detected from unknown/external IP addresses to PLC controllers',
        rogue_ips: rogueIPs,
        targeted_plcs: targetedPLCs,
        commands_sent: externalPLCCommands.length,
        affected_zones: [...new Set(externalPLCCommands.map(e => e.plc_zone).filter(Boolean))],
        commands: [...new Set(externalPLCCommands.map(e => e.plc_command).filter(Boolean))],
        data_sources: 'Firewall Logs, Network Device Logs, SCADA Network Monitoring',
        why_suspicious: 'Only authorized SCADA systems should communicate with PLCs. External communication indicates unauthorized command injection attempt.',
        mitre: 'T0855 - Unauthorized Command Message / T0832 - Manipulation of View',
        recommendation: `IMMEDIATE: Block IPs [${rogueIPs.join(', ')}] at OT firewall. Verify PLC configurations for ${targetedPLCs.join(', ')}. Check for unauthorized setpoint changes. Enable enhanced Modbus logging.`,
      });
    }

    if (unauthorizedPLCCommands.length > 0 && externalPLCCommands.length === 0) {
      const affectedPLCs = [...new Set(unauthorizedPLCCommands.map(e => e.plc_id).filter(Boolean))];
      findings.push({
        type: 'UNAUTHORIZED_PLC_COMMAND_INJECTION',
        severity: 'CRITICAL',
        description: 'Unauthorized commands detected targeting PLC controllers - possible insider threat or compromised account',
        affected_plcs: affectedPLCs,
        commands_detected: unauthorizedPLCCommands.length,
        affected_zones: [...new Set(unauthorizedPLCCommands.map(e => e.plc_zone).filter(Boolean))],
        source_ips: [...new Set(unauthorizedPLCCommands.map(e => e.source_ip))],
        data_sources: 'PLC Command Logs, SCADA Application Logs',
        why_suspicious: 'Unauthorized PLC commands could manipulate water treatment processes causing public safety risk.',
        mitre: 'T0855 - Unauthorized Command Message',
        recommendation: `Halt unauthorized PLC commands. Verify PLC firmware integrity for ${affectedPLCs.join(', ')}. Audit operator access privileges.`,
      });
    }

    if (dangerousCommands.length > 0) {
      findings.push({
        type: 'DANGEROUS_PLC_MODIFICATION',
        severity: 'CRITICAL',
        description: 'Safety-critical PLC modifications detected (setpoint/safety logic/pressure override)',
        commands: [...new Set(dangerousCommands.map(e => `${e.plc_id}: ${e.plc_command}`))],
        count: dangerousCommands.length,
        source_ips: [...new Set(dangerousCommands.map(e => e.source_ip))],
        data_sources: 'PLC Command Logs, Safety Instrumented System (SIS) Logs',
        why_suspicious: 'Modifications to safety logic or chemical setpoints can cause water contamination or equipment damage.',
        mitre: 'T0829 - Modify Control Logic',
        recommendation: 'EMERGENCY: Verify all PLC safety logic is intact. Compare current PLC programs against known-good baselines. Engage plant safety team.',
      });
    }

    return {
      hunt_name: 'H1: Unauthorized Modbus/TCP Communication to PLCs',
      hunt_id: 'HUNT-H1',
      hypothesis: 'If Modbus/TCP communication is observed from unknown IP addresses to PLC controllers, it may indicate unauthorized command injection.',
      data_sources: ['Firewall Logs', 'Network Device Logs', 'PLC Command Logs'],
      description: 'Detect unauthorized Modbus/TCP communications from unknown/rogue IP addresses to PLC controllers. Only authorized SCADA systems should communicate with PLCs.',
      expected_outcome: 'Identify rogue devices or attackers attempting to manipulate industrial processes',
      findings,
      events_analyzed: plcEvents.length,
    };
  }

  // ================================================================
  // HYPOTHESIS 2: Brute-Force Attack Pattern
  // ================================================================
  // Hunting Hypothesis:
  //   If multiple failed login attempts followed by a successful login
  //   occur on SCADA systems, it may indicate a brute-force attack.
  // Data Sources: Windows Security Logs, VPN Authentication Logs
  // Why Suspicious: This pattern is commonly used by attackers to guess
  //   passwords and gain unauthorized access.
  // Expected Outcome: Detect compromised operator accounts and prevent
  //   unauthorized access
  // ================================================================
  huntHypothesis2_BruteForcePattern() {
    const loginEvents = this.eventBuffer.filter(
      e => e.event_type === 'LOGIN_ATTEMPT'
    );

    // Group all login events by source IP
    const ipGroups = {};
    for (const event of loginEvents) {
      if (!ipGroups[event.source_ip]) ipGroups[event.source_ip] = [];
      ipGroups[event.source_ip].push(event);
    }

    const findings = [];

    for (const [ip, events] of Object.entries(ipGroups)) {
      const failedAttempts = events.filter(e => e.status === 'FAILED');
      const successfulAttempts = events.filter(e => e.status === 'SUCCESS');

      // Pattern: Multiple failed logins followed by a success = brute force with compromise
      if (failedAttempts.length >= 3 && successfulAttempts.length > 0) {
        const failedFirst = new Date(failedAttempts[0].timestamp);
        const successTime = new Date(successfulAttempts[0].timestamp);

        // Check temporal order: failures happened before success
        if (failedFirst <= successTime) {
          findings.push({
            type: 'BRUTE_FORCE_WITH_CREDENTIAL_COMPROMISE',
            severity: 'CRITICAL',
            description: `ACCOUNT COMPROMISED: ${failedAttempts.length} failed login attempts followed by successful login from ${ip} — brute-force attack succeeded!`,
            ip,
            failed_count: failedAttempts.length,
            successful_count: successfulAttempts.length,
            compromised_account: successfulAttempts[0].username,
            targeted_usernames: [...new Set(failedAttempts.map(e => e.username))],
            first_failed: failedAttempts[0].timestamp,
            last_failed: failedAttempts[failedAttempts.length - 1].timestamp,
            first_success: successfulAttempts[0].timestamp,
            data_sources: 'Windows Security Logs, VPN Authentication Logs, SCADA HMI Logs',
            why_suspicious: 'Multiple failed login attempts followed by a successful login is the hallmark pattern of a brute-force attack. Attacker has gained access to SCADA systems.',
            mitre: 'T1110 - Brute Force → T1078 - Valid Accounts',
            recommendation: `URGENT: Immediately disable account '${successfulAttempts[0].username}'. Block IP ${ip} at all perimeter firewalls. Reset all SCADA operator passwords. Audit all actions performed after successful login. Check for lateral movement.`,
          });
        }
      }
      // Pattern: Only multiple failed logins = ongoing brute force attempt
      else if (failedAttempts.length >= 3) {
        findings.push({
          type: 'BRUTE_FORCE_ATTACK_IN_PROGRESS',
          severity: 'HIGH',
          description: `ACTIVE ATTACK: ${failedAttempts.length} failed login attempts from ${ip} targeting SCADA systems — brute-force attack in progress`,
          ip,
          failed_count: failedAttempts.length,
          targeted_usernames: [...new Set(failedAttempts.map(e => e.username))],
          first_seen: failedAttempts[0].timestamp,
          last_seen: failedAttempts[failedAttempts.length - 1].timestamp,
          data_sources: 'Windows Security Logs, VPN Authentication Logs',
          why_suspicious: 'This pattern is commonly used by attackers to guess passwords and gain unauthorized access to SCADA systems.',
          mitre: 'T1110 - Brute Force',
          recommendation: `Block IP ${ip} immediately at perimeter firewall. Enforce account lockout policy. Enable MFA for all SCADA operator accounts.`,
        });
      }
    }

    return {
      hunt_name: 'H2: Brute-Force Attack Detection (Failed → Successful Login)',
      hunt_id: 'HUNT-H2',
      hypothesis: 'If multiple failed login attempts followed by a successful login occur on SCADA systems, it may indicate a brute-force attack.',
      data_sources: ['Windows Security Logs', 'VPN Authentication Logs', 'SCADA HMI Access Logs'],
      description: 'Detect brute-force login patterns: multiple failed attempts followed by successful login, indicating compromised operator accounts.',
      expected_outcome: 'Detect compromised operator accounts and prevent unauthorized access',
      findings,
      events_analyzed: loginEvents.length,
    };
  }

  // ================================================================
  // HYPOTHESIS 3: Malware on Operator Workstation
  // ================================================================
  // Hunting Hypothesis:
  //   If malware is detected on an operator workstation connected to the
  //   SCADA network, it may indicate an attempt to control PLC systems.
  // Data Sources: EDR Logs, Windows Logs
  // Why Suspicious: Operator workstations have direct access to critical
  //   systems and are high-value targets.
  // Expected Outcome: Identify infected systems and isolate them before
  //   damage occurs
  // ================================================================
  huntHypothesis3_MalwareOnWorkstation() {
    const malwareEvents = this.eventBuffer.filter(
      e => e.event_type === 'MALWARE_DETECTED'
    );

    // Also find PLC commands that happened from same IPs as malware
    const malwareIPs = new Set(malwareEvents.map(e => e.source_ip));
    const plcFromMalwareIP = this.eventBuffer.filter(
      e => e.event_type === 'PLC_COMMAND' && malwareIPs.has(e.source_ip)
    );

    // Find lateral movement from malware sources
    const lateralFromMalware = this.eventBuffer.filter(
      e => e.event_type === 'LATERAL_MOVEMENT' && malwareIPs.has(e.source_ip)
    );

    const findings = [];

    if (malwareEvents.length > 0) {
      const targetedPLCs = [...new Set(malwareEvents.map(e => e.plc_id).filter(Boolean))];
      const sourceIPs = [...new Set(malwareEvents.map(e => e.source_ip))];
      const malwareNames = [...new Set(malwareEvents.map(e => {
        // Extract malware name from description
        const match = e.description.match(/['''](\w+)[''']/);
        return match ? match[1] : 'Unknown';
      }))];

      findings.push({
        type: 'MALWARE_ON_SCADA_WORKSTATION',
        severity: 'CRITICAL',
        description: `ICS MALWARE DETECTED: ${malwareNames.join(', ')} found on operator workstation(s) connected to SCADA network — active attempt to control PLC systems!`,
        malware_names: malwareNames,
        total_detections: malwareEvents.length,
        infected_workstation_ips: sourceIPs,
        targeted_plcs: targetedPLCs,
        targeted_zones: [...new Set(malwareEvents.map(e => e.plc_zone).filter(Boolean))],
        plc_commands_from_infected: plcFromMalwareIP.length,
        lateral_movement_detected: lateralFromMalware.length > 0,
        data_sources: 'EDR Logs, Windows Event Logs, Antivirus/Anti-malware Logs',
        why_suspicious: 'Operator workstations have direct access to critical PLC systems and are high-value targets. ICS-specific malware (Triton, Industroyer, Stuxnet) directly targets safety and control systems.',
        mitre: 'T0829 - Modify Control Logic / T0831 - Manipulation of Control',
        recommendation: `EMERGENCY RESPONSE: 1) Isolate infected workstations [${sourceIPs.join(', ')}] from SCADA network immediately. 2) Quarantine malware samples. 3) Verify PLC firmware integrity for ${targetedPLCs.join(', ')}. 4) Check safety instrumented systems (SIS). 5) Engage ICS-CERT for malware analysis.`,
      });

      // Additional finding: If malware source also sent PLC commands
      if (plcFromMalwareIP.length > 0) {
        findings.push({
          type: 'MALWARE_DRIVEN_PLC_MANIPULATION',
          severity: 'CRITICAL',
          description: `ACTIVE EXPLOITATION: Infected workstation(s) sent ${plcFromMalwareIP.length} commands to PLCs after malware detection — damage may have occurred!`,
          plc_commands: plcFromMalwareIP.map(e => ({
            plc: e.plc_id,
            command: e.plc_command,
            zone: e.plc_zone,
            ip: e.source_ip,
          })),
          data_sources: 'EDR Logs, PLC Command Logs, SCADA Application Logs',
          why_suspicious: 'Malware on operator workstation is actively sending commands to PLCs, indicating the attacker has achieved their objective of controlling industrial processes.',
          mitre: 'T0855 - Unauthorized Command Message / T0831 - Manipulation of Control',
          recommendation: 'CRITICAL: Immediately disconnect affected PLCs from network. Switch to manual control. Verify all chemical dosing and pressure values against physical instruments.',
        });
      }
    }

    return {
      hunt_name: 'H3: Malware on Operator Workstation (PLC Targeting)',
      hunt_id: 'HUNT-H3',
      hypothesis: 'If malware is detected on an operator workstation connected to the SCADA network, it may indicate an attempt to control PLC systems.',
      data_sources: ['EDR Logs', 'Windows Event Logs', 'Antivirus Logs'],
      description: 'Detect malware on operator workstations that have direct access to SCADA/PLC systems. Correlate malware detections with subsequent PLC commands from the same source.',
      expected_outcome: 'Identify infected systems and isolate them before damage occurs',
      findings,
      events_analyzed: malwareEvents.length,
    };
  }

  // ================================================================
  // SUPPORTING HUNT: Sensor Anomaly Detection
  // ================================================================
  huntSensorAnomalies() {
    const sensorEvents = this.eventBuffer.filter(
      e => e.event_type === 'SENSOR_ANOMALY'
    );

    const findings = [];
    const sensorGroups = {};
    for (const event of sensorEvents) {
      const key = event.sensor_type;
      if (!sensorGroups[key]) sensorGroups[key] = [];
      sensorGroups[key].push(event);
    }

    for (const [sensor, events] of Object.entries(sensorGroups)) {
      const sensorConfig = config.scada.sensors[sensor];
      if (!sensorConfig) continue;

      const criticalEvents = events.filter(e =>
        e.sensor_value > sensorConfig.critical_high ||
        e.sensor_value < sensorConfig.critical_low
      );

      if (criticalEvents.length > 0) {
        findings.push({
          type: 'SENSOR_DATA_MANIPULATION',
          severity: 'HIGH',
          description: `${sensor} sensor readings critically out of range — possible data manipulation or physical process compromise`,
          sensor,
          critical_readings: criticalEvents.length,
          values: criticalEvents.map(e => `${e.sensor_value} ${e.sensor_unit}`),
          normal_range: `${sensorConfig.min} - ${sensorConfig.max} ${sensorConfig.unit}`,
          source_ips: [...new Set(criticalEvents.map(e => e.source_ip))],
          data_sources: 'SCADA Sensor Logs, Historian Database',
          mitre: 'T0832 - Manipulation of View',
          recommendation: `Verify physical ${sensor} sensor. Cross-reference with field instruments. Check for unauthorized access to sensor network segment.`,
        });
      }
    }

    return {
      hunt_name: 'Supporting: Sensor Anomaly Detection',
      hunt_id: 'HUNT-S1',
      description: 'Detect abnormal sensor readings indicating possible data manipulation or physical process compromise',
      findings,
      events_analyzed: sensorEvents.length,
    };
  }

  // ================================================================
  // SUPPORTING HUNT: IT to OT Lateral Movement
  // ================================================================
  huntLateralMovement() {
    const lateralEvents = this.eventBuffer.filter(
      e => e.event_type === 'LATERAL_MOVEMENT'
    );

    const findings = [];
    if (lateralEvents.length > 0) {
      findings.push({
        type: 'IT_OT_BOUNDARY_CROSSING',
        severity: 'HIGH',
        description: 'Unauthorized lateral movement detected from IT network to OT/SCADA network segment',
        occurrences: lateralEvents.length,
        source_ips: [...new Set(lateralEvents.map(e => e.source_ip))],
        destination_ips: [...new Set(lateralEvents.map(e => e.destination_ip))],
        data_sources: 'Firewall Logs, Network IDS, VPN Logs',
        mitre: 'T0866 - Exploitation of Remote Services',
        recommendation: 'Review IT/OT firewall rules. Audit VPN and remote access logs. Verify network segmentation between IT and OT.',
      });
    }

    return {
      hunt_name: 'Supporting: IT to OT Lateral Movement',
      hunt_id: 'HUNT-S2',
      description: 'Detect unauthorized movement from IT to OT network segments',
      findings,
      events_analyzed: lateralEvents.length,
    };
  }

  // ================================================================
  // SUPPORTING HUNT: Threat Intelligence Correlation
  // ================================================================
  huntThreatIntelMatches() {
    const ctiEvents = this.eventBuffer.filter(
      e => e.threat_intel_tag === 'THREAT_INTEL_MATCH'
    );

    const findings = [];
    if (ctiEvents.length > 0) {
      const maliciousIPs = [...new Set(ctiEvents.map(e => e.source_ip))];
      findings.push({
        type: 'CTI_INDICATOR_MATCH',
        severity: 'CRITICAL',
        description: 'Events correlated with known malicious IP addresses from threat intelligence feeds',
        total_matches: ctiEvents.length,
        malicious_ips: maliciousIPs,
        event_types: [...new Set(ctiEvents.map(e => e.event_type))],
        data_sources: 'Threat Intelligence Feeds, CTI Platforms, ISAC Alerts',
        mitre: 'Multiple ATT&CK techniques (T1078, T1110, T0855, T0829)',
        recommendation: `Block all matched IPs [${maliciousIPs.join(', ')}] at perimeter firewall. Investigate all associated sessions. Submit IOCs to ICS-CERT.`,
      });
    }

    return {
      hunt_name: 'Supporting: Threat Intelligence Correlation',
      hunt_id: 'HUNT-S3',
      description: 'Correlate events with known threat intelligence indicators and IOCs',
      findings,
      events_analyzed: ctiEvents.length,
    };
  }

  /**
   * Get timeline of events for investigation
   */
  getTimeline(filters = {}) {
    let events = [...this.eventBuffer];

    if (filters.source_ip) {
      events = events.filter(e => e.source_ip === filters.source_ip);
    }
    if (filters.event_type) {
      events = events.filter(e => e.event_type === filters.event_type);
    }
    if (filters.severity) {
      events = events.filter(e => e.threat_severity === filters.severity);
    }
    if (filters.mitre_id) {
      events = events.filter(e => e.mitre_id === filters.mitre_id);
    }

    return events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  }

  /**
   * Get SOC metrics summary
   */
  getMetrics() {
    const total = this.eventBuffer.length;
    const severityCounts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    const eventTypeCounts = {};
    const ipCounts = {};
    const mitreCounts = {};

    for (const event of this.eventBuffer) {
      severityCounts[event.threat_severity] = (severityCounts[event.threat_severity] || 0) + 1;
      eventTypeCounts[event.event_type] = (eventTypeCounts[event.event_type] || 0) + 1;
      ipCounts[event.source_ip] = (ipCounts[event.source_ip] || 0) + 1;
      if (event.mitre_id !== 'N/A') {
        const key = `${event.mitre_id} - ${event.mitre_technique}`;
        mitreCounts[key] = (mitreCounts[key] || 0) + 1;
      }
    }

    // Top source IPs
    const topIPs = Object.entries(ipCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count, isMalicious: config.threatIntel.maliciousIPs.includes(ip) }));

    return {
      total_events: total,
      severity_distribution: severityCounts,
      event_type_distribution: eventTypeCounts,
      mitre_technique_distribution: mitreCounts,
      top_source_ips: topIPs,
      threat_intel_matches: this.eventBuffer.filter(e => e.threat_intel_tag === 'THREAT_INTEL_MATCH').length,
      active_hunts: this.huntResults.length,
    };
  }

  /**
   * Clear event buffer
   */
  clearBuffer() {
    this.eventBuffer = [];
    this.huntResults = [];
  }
}

module.exports = ThreatHunter;
