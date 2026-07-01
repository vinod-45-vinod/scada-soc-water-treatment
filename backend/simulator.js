/**
 * SCADA Event Simulator
 * Generates realistic SCADA/ICS events including normal operations and attack scenarios
 */

const config = require('./config');

class ScadaSimulator {
  constructor() {
    this.sensorStates = {};
    this.initSensors();
    this.attackMode = null;
    this.attackStep = 0;
  }

  initSensors() {
    for (const [name, range] of Object.entries(config.scada.sensors)) {
      this.sensorStates[name] = {
        value: (range.min + range.max) / 2,
        trend: 0,
      };
    }
  }

  /**
   * Generate a normal operational event
   */
  generateNormalEvent() {
    const eventTypes = [
      { type: 'sensor_reading', weight: 50 },
      { type: 'plc_status', weight: 20 },
      { type: 'operator_action', weight: 15 },
      { type: 'system_health', weight: 15 },
    ];

    const roll = Math.random() * 100;
    let cumulative = 0;
    let selectedType = eventTypes[0].type;
    for (const et of eventTypes) {
      cumulative += et.weight;
      if (roll <= cumulative) {
        selectedType = et.type;
        break;
      }
    }

    switch (selectedType) {
      case 'sensor_reading':
        return this._generateSensorReading();
      case 'plc_status':
        return this._generatePLCStatus();
      case 'operator_action':
        return this._generateOperatorAction();
      case 'system_health':
        return this._generateSystemHealth();
    }
  }

  /**
   * Generate attack scenario events (full kill chain)
   */
  generateAttackEvent(scenarioName) {
    const scenarios = {
      brute_force: this._bruteForceScenario.bind(this),
      sensor_manipulation: this._sensorManipulationScenario.bind(this),
      malware_injection: this._malwareInjectionScenario.bind(this),
      full_attack_chain: this._fullAttackChainScenario.bind(this),
      lateral_movement: this._lateralMovementScenario.bind(this),
    };

    const scenario = scenarios[scenarioName] || scenarios.full_attack_chain;
    return scenario();
  }

  /**
   * Get list of available attack scenarios
   */
  getScenarios() {
    return [
      { id: 'brute_force', name: 'Brute Force Login Attack', description: 'Multiple failed login attempts from malicious IP', stages: ['Initial Access'] },
      { id: 'sensor_manipulation', name: 'Sensor Data Manipulation', description: 'Attacker modifies pH and chlorine sensor readings', stages: ['Execution', 'Impact'] },
      { id: 'malware_injection', name: 'PLC Malware Injection', description: 'Malware deployed to modify PLC logic', stages: ['Persistence', 'Impact'] },
      { id: 'full_attack_chain', name: 'Full Attack Chain', description: 'Complete attack lifecycle: recon → access → execution → persistence → impact', stages: config.attackStages },
      { id: 'lateral_movement', name: 'IT to OT Lateral Movement', description: 'Attacker moves from IT network into OT/SCADA network', stages: ['Lateral Movement', 'Execution'] },
    ];
  }

  // ===== Normal Event Generators =====

  _generateSensorReading() {
    const sensorNames = Object.keys(config.scada.sensors);
    const sensorName = sensorNames[Math.floor(Math.random() * sensorNames.length)];
    const sensorConfig = config.scada.sensors[sensorName];
    const state = this.sensorStates[sensorName];

    // Add small random drift
    state.trend += (Math.random() - 0.5) * 0.1;
    state.trend = Math.max(-0.5, Math.min(0.5, state.trend));
    state.value += state.trend + (Math.random() - 0.5) * 0.3;
    state.value = Math.max(sensorConfig.min * 0.8, Math.min(sensorConfig.max * 1.2, state.value));

    const isNormal = state.value >= sensorConfig.min && state.value <= sensorConfig.max;

    return {
      event_type: isNormal ? 'SENSOR_READING' : 'SENSOR_ANOMALY',
      description: `Sensor ${sensorName} reading: ${state.value.toFixed(2)} ${sensorConfig.unit}`,
      source_ip: this._randomInternalIP(),
      sensor_type: sensorName,
      sensor_value: parseFloat(state.value.toFixed(2)),
      sensor_unit: sensorConfig.unit,
      sensor_status: isNormal ? 'NORMAL' : 'WARNING',
      status: isNormal ? 'OK' : 'ANOMALY',
      username: 'SYSTEM',
    };
  }

  _generatePLCStatus() {
    const plc = config.scada.plcs[Math.floor(Math.random() * config.scada.plcs.length)];
    const commands = ['READ_STATUS', 'HEARTBEAT', 'CONFIG_CHECK', 'DIAGNOSTIC'];
    const cmd = commands[Math.floor(Math.random() * commands.length)];

    return {
      event_type: 'PLC_COMMAND',
      description: `PLC ${plc.id} executed ${cmd} in zone ${plc.zone}`,
      source_ip: this._randomInternalIP(),
      plc_id: plc.id,
      plc_command: cmd,
      plc_zone: plc.zone,
      status: 'AUTHORIZED',
      username: 'SYSTEM',
    };
  }

  _generateOperatorAction() {
    const station = config.scada.hmi_stations[Math.floor(Math.random() * config.scada.hmi_stations.length)];
    const actions = ['VIEW_DASHBOARD', 'ACK_ALARM', 'ADJUST_SETPOINT', 'GENERATE_REPORT'];
    const action = actions[Math.floor(Math.random() * actions.length)];

    return {
      event_type: 'LOGIN_ATTEMPT',
      description: `Operator ${station.operator} performed ${action} on ${station.name}`,
      source_ip: this._randomInternalIP(),
      username: station.operator,
      status: 'SUCCESS',
    };
  }

  _generateSystemHealth() {
    const components = ['Database', 'Historian', 'Network Switch', 'Firewall', 'Backup System'];
    const comp = components[Math.floor(Math.random() * components.length)];

    return {
      event_type: 'SYSTEM_HEALTH',
      description: `Health check passed for ${comp}`,
      source_ip: this._randomInternalIP(),
      status: 'OK',
      username: 'SYSTEM',
    };
  }

  // ===== Attack Scenario Generators =====

  _bruteForceScenario() {
    const attackerIP = this._randomMaliciousIP();
    const usernames = ['admin', 'operator1', 'root', 'scada_admin', 'engineer1'];
    const user = usernames[Math.floor(Math.random() * usernames.length)];

    return {
      event_type: 'LOGIN_ATTEMPT',
      description: `Failed login attempt for user '${user}' from external IP`,
      source_ip: attackerIP,
      username: user,
      status: 'FAILED',
    };
  }

  _sensorManipulationScenario() {
    const sensors = ['pH', 'chlorine', 'turbidity'];
    const sensor = sensors[Math.floor(Math.random() * sensors.length)];
    const sensorConfig = config.scada.sensors[sensor];

    // Generate critically out-of-range value
    const extremeValue = Math.random() > 0.5
      ? sensorConfig.critical_high + Math.random() * 5
      : sensorConfig.critical_low - Math.random() * 2;

    return {
      event_type: 'SENSOR_ANOMALY',
      description: `CRITICAL: Sensor ${sensor} reading ${extremeValue.toFixed(2)} ${sensorConfig.unit} - possible manipulation`,
      source_ip: this._randomMaliciousIP(),
      sensor_type: sensor,
      sensor_value: parseFloat(extremeValue.toFixed(2)),
      sensor_unit: sensorConfig.unit,
      sensor_status: 'CRITICAL',
      status: 'ANOMALY',
      username: 'UNKNOWN',
    };
  }

  _malwareInjectionScenario() {
    const plc = config.scada.plcs[Math.floor(Math.random() * config.scada.plcs.length)];
    const malwareNames = ['Triton', 'Industroyer', 'Stuxnet-variant', 'BlackEnergy', 'HavexRAT'];
    const malware = malwareNames[Math.floor(Math.random() * malwareNames.length)];

    return {
      event_type: 'MALWARE_DETECTED',
      description: `Malware '${malware}' detected targeting ${plc.id} (${plc.name})`,
      source_ip: this._randomMaliciousIP(),
      plc_id: plc.id,
      plc_command: 'INJECT_PAYLOAD',
      plc_zone: plc.zone,
      status: 'ALERT',
      username: 'UNKNOWN',
    };
  }

  _lateralMovementScenario() {
    const sourceIP = this._randomMaliciousIP();

    return {
      event_type: 'LATERAL_MOVEMENT',
      description: `Suspicious lateral movement detected: IT network to OT SCADA network`,
      source_ip: sourceIP,
      destination_ip: this._randomInternalIP(),
      status: 'ALERT',
      username: 'UNKNOWN',
    };
  }

  _fullAttackChainScenario() {
    this.attackStep = (this.attackStep || 0);
    const attackerIP = config.threatIntel.maliciousIPs[0]; // Consistent attacker

    const chain = [
      // Step 1: Reconnaissance
      {
        event_type: 'LOGIN_ATTEMPT',
        description: 'Port scan detected - reconnaissance activity from external IP',
        source_ip: attackerIP,
        status: 'FAILED',
        username: 'scanner',
      },
      // Step 2: Initial Access - Brute Force
      {
        event_type: 'LOGIN_ATTEMPT',
        description: 'Brute force login attempt on SCADA HMI interface',
        source_ip: attackerIP,
        status: 'FAILED',
        username: 'admin',
      },
      // Step 3: More brute force
      {
        event_type: 'LOGIN_ATTEMPT',
        description: 'Continued brute force - trying operator credentials',
        source_ip: attackerIP,
        status: 'FAILED',
        username: 'operator1',
      },
      // Step 4: Successful login
      {
        event_type: 'LOGIN_ATTEMPT',
        description: 'Successful login with compromised credentials',
        source_ip: attackerIP,
        status: 'SUCCESS',
        username: 'operator1',
      },
      // Step 5: Lateral Movement
      {
        event_type: 'LATERAL_MOVEMENT',
        description: 'Lateral movement from IT DMZ to OT SCADA network segment',
        source_ip: attackerIP,
        destination_ip: '10.0.1.10',
        status: 'ALERT',
        username: 'operator1',
      },
      // Step 6: Unauthorized PLC Command
      {
        event_type: 'PLC_COMMAND',
        description: 'Unauthorized command sent to Chemical Dosing PLC (PLC-001)',
        source_ip: attackerIP,
        plc_id: 'PLC-001',
        plc_command: 'MODIFY_SETPOINT',
        plc_zone: 'CHEMICAL',
        status: 'UNAUTHORIZED',
        username: 'operator1',
      },
      // Step 7: Sensor Manipulation
      {
        event_type: 'SENSOR_ANOMALY',
        description: 'CRITICAL: pH sensor reading 12.5 pH - chemical dosing overridden',
        source_ip: attackerIP,
        sensor_type: 'pH',
        sensor_value: 12.5,
        sensor_unit: 'pH',
        sensor_status: 'CRITICAL',
        status: 'ANOMALY',
        username: 'SYSTEM',
      },
      // Step 8: Malware Deployment
      {
        event_type: 'MALWARE_DETECTED',
        description: "Malware 'Triton' detected on PLC-001 - attempting to modify safety logic",
        source_ip: attackerIP,
        plc_id: 'PLC-001',
        plc_command: 'MODIFY_SAFETY_LOGIC',
        plc_zone: 'CHEMICAL',
        status: 'ALERT',
        username: 'UNKNOWN',
      },
      // Step 9: More sensor anomalies - impact
      {
        event_type: 'SENSOR_ANOMALY',
        description: 'CRITICAL: Chlorine levels at 0.0 mg/L - water treatment compromised',
        source_ip: attackerIP,
        sensor_type: 'chlorine',
        sensor_value: 0.0,
        sensor_unit: 'mg/L',
        sensor_status: 'CRITICAL',
        status: 'ANOMALY',
        username: 'SYSTEM',
      },
      // Step 10: Second PLC compromise
      {
        event_type: 'PLC_COMMAND',
        description: 'Unauthorized command to Pump Station PLC (PLC-003) - pressure override',
        source_ip: attackerIP,
        plc_id: 'PLC-003',
        plc_command: 'OVERRIDE_PRESSURE',
        plc_zone: 'PUMPING',
        status: 'UNAUTHORIZED',
        username: 'UNKNOWN',
      },
    ];

    const event = chain[this.attackStep % chain.length];
    this.attackStep++;

    return event;
  }

  // ===== Helpers =====

  _randomMaliciousIP() {
    const ips = config.threatIntel.maliciousIPs;
    return ips[Math.floor(Math.random() * ips.length)];
  }

  _randomInternalIP() {
    const ips = config.threatIntel.internalIPs;
    return ips[Math.floor(Math.random() * ips.length)];
  }

  resetAttackChain() {
    this.attackStep = 0;
  }
}

module.exports = ScadaSimulator;
