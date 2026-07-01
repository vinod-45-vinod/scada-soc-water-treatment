/**
 * Wazuh Log Sender
 * Sends formatted logs to Wazuh Manager via UDP syslog and writes to local file
 */

const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const config = require('./config');

class WazuhSender {
  constructor() {
    this.udpClient = dgram.createSocket('udp4');
    this.wazuhHost = config.wazuh.host;
    this.wazuhPort = config.wazuh.udpPort;
    this.logFile = path.resolve(config.logs.scadaLogFile);
    this.alertFile = path.resolve(config.logs.alertLogFile);

    // Ensure log directory exists
    const logDir = path.dirname(this.logFile);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }

    this.stats = {
      udpSent: 0,
      udpFailed: 0,
      fileWrites: 0,
    };

    // Handle UDP errors gracefully
    this.udpClient.on('error', (err) => {
      console.error(`[UDP ERROR] ${err.message}`);
      this.stats.udpFailed++;
    });
  }

  /**
   * Send enriched log to Wazuh via UDP and write to file
   */
  sendLog(enrichedLog, wazuhMessage) {
    // 1. Send via UDP to Wazuh Manager
    this._sendUDP(wazuhMessage);

    // 2. Write plain-text syslog format to local file (for Wazuh Agent file monitoring)
    //    Must use same format as UDP so the same Wazuh rules can match
    this._writeToFile(wazuhMessage);

    // 3. If it's a high-severity event, also write to alert file
    if (['HIGH', 'CRITICAL'].includes(enrichedLog.threat_severity)) {
      this._writeToAlertFile(enrichedLog);
    }

    return {
      udpSent: true,
      fileSaved: true,
      wazuhHost: this.wazuhHost,
      wazuhPort: this.wazuhPort,
    };
  }

  /**
   * Send plain-text message via UDP to Wazuh Manager container
   */
  _sendUDP(message) {
    try {
      const buffer = Buffer.from(message);
      this.udpClient.send(buffer, 0, buffer.length, this.wazuhPort, this.wazuhHost, (err) => {
        if (err) {
          console.error(`[UDP SEND ERROR] ${err.message}`);
          this.stats.udpFailed++;
        } else {
          this.stats.udpSent++;
        }
      });
    } catch (err) {
      console.error(`[UDP ERROR] ${err.message}`);
      this.stats.udpFailed++;
    }
  }

  /**
   * Write syslog-format log to local file (for Wazuh Agent monitoring)
   * Uses same SCADA_SOC: format as UDP so the same rules match
   */
  _writeToFile(wazuhMessage) {
    try {
      const logLine = wazuhMessage + '\n';
      fs.appendFileSync(this.logFile, logLine, 'utf8');
      this.stats.fileWrites++;
    } catch (err) {
      console.error(`[FILE WRITE ERROR] ${err.message}`);
    }
  }

  /**
   * Write high-severity alerts to separate alert file
   */
  _writeToAlertFile(enrichedLog) {
    try {
      const alertLine = `[${enrichedLog.timestamp}] [${enrichedLog.threat_severity}] ${enrichedLog.event_type}: ${enrichedLog.description} | IP: ${enrichedLog.source_ip} | MITRE: ${enrichedLog.mitre_id} | IoC: ${enrichedLog.ioc_type} | IoA: ${enrichedLog.ioa_type}\n`;
      fs.appendFileSync(this.alertFile, alertLine, 'utf8');
    } catch (err) {
      console.error(`[ALERT FILE ERROR] ${err.message}`);
    }
  }

  /**
   * Update Wazuh target (e.g., if Docker IP changes)
   */
  setWazuhTarget(host, port) {
    this.wazuhHost = host;
    this.wazuhPort = port || 514;
    console.log(`[WAZUH] Target updated to ${this.wazuhHost}:${this.wazuhPort}`);
  }

  /**
   * Get transmission statistics
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Close UDP socket
   */
  close() {
    this.udpClient.close();
  }
}

module.exports = WazuhSender;
