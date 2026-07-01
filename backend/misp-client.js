/**
 * MISP (Malware Information Sharing Platform) Client
 * Connects to MISP at localhost:8443 to fetch threat intelligence indicators
 * and enrich SCADA events with real CTI data.
 */

const https = require('https');
const config = require('./config');

class MISPClient {
  constructor() {
    this.baseUrl = config.misp?.url || 'https://localhost:8443';
    this.apiKey = config.misp?.apiKey || '';
    this.verifySsl = config.misp?.verifySsl ?? false; // Self-signed certs in containers
    this.connected = false;
    this.lastSync = null;
    this.syncInterval = config.misp?.syncIntervalMs || 60000; // Sync every 60s
    this.syncTimer = null;

    // Threat intel indicators fetched from MISP
    this.indicators = {
      maliciousIPs: new Set(),
      maliciousDomains: new Set(),
      maliciousHashes: new Set(),
      maliciousUrls: new Set(),
    };

    // Raw MISP events cache
    this.mispEvents = [];
    this.mispAttributes = [];

    // Stats
    this.stats = {
      totalSyncs: 0,
      lastSyncTime: null,
      lastSyncStatus: 'never',
      totalIndicators: 0,
      ipIndicators: 0,
      domainIndicators: 0,
      hashIndicators: 0,
      urlIndicators: 0,
      errors: 0,
      lastError: null,
    };
  }

  /**
   * Initialize MISP connection and start periodic sync
   * Retries up to 5 times with 5s delay for Docker startup
   */
  async init() {
    if (!this.apiKey) {
      console.log('[MISP] ⚠ No API key configured. Set MISP_API_KEY env variable or update config.js');
      console.log('[MISP] Using hardcoded threat intel indicators as fallback');
      return false;
    }

    const maxRetries = 5;
    const retryDelay = 5000;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      console.log(`[MISP] Connecting to ${this.baseUrl}... (attempt ${attempt}/${maxRetries})`);

      try {
        // Test connection
        const version = await this._apiRequest('/servers/getVersion');
        console.log(`[MISP] ✓ Connected to MISP v${version.version || 'unknown'}`);
        this.connected = true;

        // Initial sync
        await this.syncIndicators();

        // Start periodic sync
        this.syncTimer = setInterval(() => {
          this.syncIndicators().catch(err => {
            console.error('[MISP] Periodic sync failed:', err.message);
          });
        }, this.syncInterval);

        return true;
      } catch (err) {
        console.error(`[MISP] ✗ Attempt ${attempt} failed: ${err.message}`);
        this.stats.lastError = err.message;
        this.stats.errors++;
        this.connected = false;

        if (attempt < maxRetries) {
          console.log(`[MISP] Retrying in ${retryDelay / 1000}s...`);
          await new Promise(r => setTimeout(r, retryDelay));
        }
      }
    }

    console.error('[MISP] ✗ All connection attempts failed. Will retry on next sync cycle.');
    // Still start periodic sync so it reconnects later
    this.syncTimer = setInterval(async () => {
      try {
        if (!this.connected) {
          const version = await this._apiRequest('/servers/getVersion');
          this.connected = true;
          console.log(`[MISP] ✓ Reconnected to MISP v${version.version || 'unknown'}`);
        }
        await this.syncIndicators();
      } catch (err) {
        console.error('[MISP] Periodic sync failed:', err.message);
      }
    }, this.syncInterval);

    return false;
  }

  /**
   * Sync threat intelligence indicators from MISP
   */
  async syncIndicators() {
    try {
      console.log('[MISP] Syncing indicators...');

      // Fetch IP indicators
      const ipAttrs = await this._searchAttributes({
        type: ['ip-src', 'ip-dst'],
        to_ids: true,
        limit: 500,
        enforceWarninglist: false,
      });

      // Fetch domain indicators
      const domainAttrs = await this._searchAttributes({
        type: ['domain', 'hostname'],
        to_ids: true,
        limit: 200,
        enforceWarninglist: true,
      });

      // Fetch hash indicators (for malware correlation)
      const hashAttrs = await this._searchAttributes({
        type: ['md5', 'sha1', 'sha256'],
        to_ids: true,
        limit: 200,
        enforceWarninglist: true,
      });

      // Fetch URL indicators
      const urlAttrs = await this._searchAttributes({
        type: ['url', 'uri'],
        to_ids: true,
        limit: 200,
        enforceWarninglist: true,
      });

      // Clear and rebuild indicator sets
      this.indicators.maliciousIPs.clear();
      this.indicators.maliciousDomains.clear();
      this.indicators.maliciousHashes.clear();
      this.indicators.maliciousUrls.clear();

      // Process IP attributes
      const ipList = ipAttrs?.response?.Attribute || ipAttrs?.Attribute || [];
      for (const attr of ipList) {
        this.indicators.maliciousIPs.add(attr.value);
      }

      // Process domain attributes
      const domList = domainAttrs?.response?.Attribute || domainAttrs?.Attribute || [];
      for (const attr of domList) {
        this.indicators.maliciousDomains.add(attr.value);
      }

      // Process hash attributes
      const hashList = hashAttrs?.response?.Attribute || hashAttrs?.Attribute || [];
      for (const attr of hashList) {
        this.indicators.maliciousHashes.add(attr.value);
      }

      // Process URL attributes
      const urlList = urlAttrs?.response?.Attribute || urlAttrs?.Attribute || [];
      for (const attr of urlList) {
        this.indicators.maliciousUrls.add(attr.value);
      }

      // Update stats
      this.stats.totalSyncs++;
      this.stats.lastSyncTime = new Date().toISOString();
      this.stats.lastSyncStatus = 'success';
      this.stats.ipIndicators = this.indicators.maliciousIPs.size;
      this.stats.domainIndicators = this.indicators.maliciousDomains.size;
      this.stats.hashIndicators = this.indicators.maliciousHashes.size;
      this.stats.urlIndicators = this.indicators.maliciousUrls.size;
      this.stats.totalIndicators =
        this.stats.ipIndicators +
        this.stats.domainIndicators +
        this.stats.hashIndicators +
        this.stats.urlIndicators;
      this.lastSync = new Date();

      console.log(`[MISP] ✓ Synced ${this.stats.totalIndicators} indicators:`);
      console.log(`[MISP]   IPs: ${this.stats.ipIndicators}, Domains: ${this.stats.domainIndicators}, Hashes: ${this.stats.hashIndicators}, URLs: ${this.stats.urlIndicators}`);

      return this.stats;
    } catch (err) {
      this.stats.lastSyncStatus = 'error';
      this.stats.lastError = err.message;
      this.stats.errors++;
      console.error('[MISP] Sync error:', err.message);
      throw err;
    }
  }

  /**
   * Check if an IP is flagged in MISP
   */
  isIPMalicious(ip) {
    return this.indicators.maliciousIPs.has(ip);
  }

  /**
   * Check if a domain is flagged in MISP
   */
  isDomainMalicious(domain) {
    return this.indicators.maliciousDomains.has(domain);
  }

  /**
   * Get all malicious IPs from MISP (for enricher integration)
   */
  getMaliciousIPs() {
    return [...this.indicators.maliciousIPs];
  }

  /**
   * Search for a specific indicator in MISP and return full context
   */
  async searchIndicator(value) {
    try {
      const result = await this._searchAttributes({
        value,
        limit: 10,
      });

      const attrs = result?.response?.Attribute || result?.Attribute || [];

      if (attrs.length > 0) {
        return {
          found: true,
          indicator: value,
          matches: attrs.map(attr => ({
            id: attr.id,
            event_id: attr.event_id,
            type: attr.type,
            category: attr.category,
            value: attr.value,
            to_ids: attr.to_ids,
            timestamp: attr.timestamp,
            comment: attr.comment || '',
          })),
        };
      }

      return { found: false, indicator: value, matches: [] };
    } catch (err) {
      return { found: false, indicator: value, error: err.message };
    }
  }

  /**
   * Fetch recent MISP events (for dashboard display)
   */
  async getRecentEvents(limit = 10) {
    try {
      const result = await this._apiRequest('/events/index', 'POST', {
        limit,
        sort: 'timestamp',
        direction: 'desc',
      });
      return result || [];
    } catch (err) {
      console.error('[MISP] Failed to fetch events:', err.message);
      return [];
    }
  }

  /**
   * Create a MISP event from a SCADA alert (push back IOCs to MISP)
   */
  async createEvent(scadaEvent) {
    try {
      const mispEvent = {
        Event: {
          info: `SOC-MINI SCADA Alert: ${scadaEvent.event_type} - ${scadaEvent.description}`,
          distribution: 0, // Organization only
          threat_level_id: this._mapSeverityToThreatLevel(scadaEvent.threat_severity),
          analysis: 2, // Completed
          Attribute: [],
        },
      };

      // Add source IP as attribute
      if (scadaEvent.source_ip && scadaEvent.source_ip !== '0.0.0.0') {
        const normalizedIP = this._normalizeIP(scadaEvent.source_ip);
        mispEvent.Event.Attribute.push({
          type: 'ip-src',
          category: 'Network activity',
          value: normalizedIP,
          to_ids: scadaEvent.is_malicious_ip || false,
          comment: `Source IP from SCADA ${scadaEvent.event_type} event`,
        });
      }

      // Add MITRE ATT&CK tag
      if (scadaEvent.mitre_id && scadaEvent.mitre_id !== 'N/A') {
        mispEvent.Event.Tag = [
          { name: `misp-galaxy:mitre-attack-pattern="${scadaEvent.mitre_technique}"` },
        ];
      }

      const result = await this._apiRequest('/events/add', 'POST', mispEvent);
      console.log(`[MISP] Created event: ${result?.Event?.id || 'unknown'}`);
      return result;
    } catch (err) {
      console.error('[MISP] Failed to create event:', err.message);
      return null;
    }
  }

  /**
   * Search attributes via MISP REST API
   */
  async _searchAttributes(searchParams) {
    return this._apiRequest('/attributes/restSearch', 'POST', {
      ...searchParams,
      returnFormat: 'json',
    });
  }

  /**
   * Make authenticated API request to MISP
   */
  _apiRequest(endpoint, method = 'GET', body = null) {
    return new Promise((resolve, reject) => {
      const url = new URL(endpoint, this.baseUrl);

      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method,
        rejectUnauthorized: this.verifySsl,
        headers: {
          'Authorization': this.apiKey,
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
        timeout: 10000,
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            if (res.statusCode >= 200 && res.statusCode < 300) {
              const parsed = JSON.parse(data);
              resolve(parsed);
            } else if (res.statusCode === 403) {
              reject(new Error('MISP API: Authentication failed (403). Check API key.'));
            } else {
              reject(new Error(`MISP API: HTTP ${res.statusCode} - ${data.substring(0, 200)}`));
            }
          } catch (e) {
            reject(new Error(`MISP API: Failed to parse response - ${e.message}`));
          }
        });
      });

      req.on('error', (err) => {
        reject(new Error(`MISP connection error: ${err.message}`));
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('MISP API: Request timeout'));
      });

      if (body) {
        req.write(JSON.stringify(body));
      }

      req.end();
    });
  }

  /**
   * Map SCADA severity to MISP threat level
   */
  _mapSeverityToThreatLevel(severity) {
    const mapping = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 };
    return mapping[severity] || 4;
  }

  /**
   * Get current status and stats
   */
  getStatus() {
    return {
      connected: this.connected,
      url: this.baseUrl,
      hasApiKey: !!this.apiKey,
      lastSync: this.lastSync?.toISOString() || null,
      ...this.stats,
      indicators: {
        ips: [...this.indicators.maliciousIPs],
        domains: [...this.indicators.maliciousDomains],
        hashes_count: this.indicators.maliciousHashes.size,
        urls_count: this.indicators.maliciousUrls.size,
      },
    };
  }

  /**
   * Update MISP configuration at runtime
   */
  updateConfig(url, apiKey) {
    this.baseUrl = url || this.baseUrl;
    this.apiKey = apiKey || this.apiKey;
    this.connected = false;
    console.log(`[MISP] Config updated: ${this.baseUrl}`);
  }

  /**
   * Stop periodic sync
   */
  destroy() {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
    }
  }
  /**
   * Block an IP — create a MISP event with ip-dst attribute (to_ids=true)
   * This IP will be picked up by firewall/IDS integrations
   */
  async blockIP(ip, reason, analyst) {
    if (!this.connected) throw new Error('MISP not connected');

    // Normalize IP (remove leading zeros like 45.11.11.000 → 45.11.11.0)
    const normalizedIP = this._normalizeIP(ip);
    const eventData = {
      Event: {
        info: `[BLOCKED] SOC-MINI: IP ${normalizedIP} blocked — ${reason || 'Malicious activity'}`,
        distribution: '0',
        threat_level_id: '1',
        analysis: '2',
        date: new Date().toISOString().split('T')[0],
        Tag: [
          { name: 'soc-mini:action="blocked"' },
          { name: 'tlp:red' },
          { name: 'misp-galaxy:mitre-attack-pattern="Brute Force"' },
        ],
        Attribute: [{
          type: 'ip-dst',
          category: 'Network activity',
          value: normalizedIP,
          to_ids: true,
          comment: `Blocked by ${analyst || 'SOC Analyst'}: ${reason || 'Malicious activity detected'}`,
        }],
      },
    };

    const result = await this._apiRequest('/events/add', 'POST', eventData);
    console.log(`[MISP] 🚫 IP ${normalizedIP} BLOCKED — Event ID: ${result?.Event?.id || 'created'}`);

    // Also add to local blocklist
    this.indicators.maliciousIPs.add(normalizedIP);

    return result;
  }

  /**
   * Get all blocked IPs from MISP (attributes with to_ids=true, type=ip-dst)
   */
  async getBlockedIPs() {
    if (!this.connected) return [];

    try {
      const result = await this._apiRequest('/attributes/restSearch', 'POST', {
        returnFormat: 'json',
        type: 'ip-dst',
        to_ids: true,
        limit: 100,
      });

      const attributes = result?.response?.Attribute || [];
      return attributes.map(attr => ({
        ip: attr.value,
        event_id: attr.event_id,
        comment: attr.comment || '',
        timestamp: new Date(parseInt(attr.timestamp) * 1000).toISOString(),
        category: attr.category,
      }));
    } catch (err) {
      console.error('[MISP] Error fetching blocked IPs:', err.message);
      return [];
    }
  }

  /**
   * Normalize an IP address — strip leading zeros (45.11.11.000 → 45.11.11.0)
   * MISP silently rejects attributes with non-standard IP formats
   */
  _normalizeIP(ip) {
    if (!ip) return ip;
    const parts = ip.split('.');
    if (parts.length !== 4) return ip;
    return parts.map(p => String(parseInt(p, 10) || 0)).join('.');
  }
}

module.exports = MISPClient;
