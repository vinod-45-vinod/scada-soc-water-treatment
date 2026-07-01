/**
 * VirusTotal API Client
 * Checks IP reputation for SCADA SOC enrichment
 */

const https = require('https');
const config = require('./config');

class VirusTotalClient {
  constructor() {
    this.apiKey = config.virustotal?.apiKey || process.env.VT_API_KEY || '';
    this.baseUrl = 'https://www.virustotal.com/api/v3';
    this.cache = new Map(); // Cache results to avoid rate limits
    this.cacheTTL = 300000; // 5 min cache
    this.stats = {
      totalQueries: 0,
      maliciousFound: 0,
      cleanFound: 0,
      errors: 0,
      lastQuery: null,
    };
  }

  /**
   * Check IP reputation via VirusTotal
   */
  async checkIP(ip) {
    // Check cache first
    const cached = this.cache.get(ip);
    if (cached && (Date.now() - cached.timestamp < this.cacheTTL)) {
      return cached.result;
    }

    if (!this.apiKey) {
      return { ip, status: 'no_api_key', malicious: false, error: 'VirusTotal API key not configured' };
    }

    try {
      this.stats.totalQueries++;
      this.stats.lastQuery = new Date().toISOString();

      const data = await this._apiRequest(`/ip_addresses/${ip}`);
      const stats = data?.data?.attributes?.last_analysis_stats || {};
      const totalMalicious = (stats.malicious || 0) + (stats.suspicious || 0);
      const totalClean = stats.harmless || 0;
      const totalEngines = totalMalicious + totalClean + (stats.undetected || 0);

      const result = {
        ip,
        status: 'checked',
        malicious: totalMalicious > 2,
        suspicious: totalMalicious > 0,
        reputation: data?.data?.attributes?.reputation || 0,
        malicious_count: totalMalicious,
        clean_count: totalClean,
        total_engines: totalEngines,
        country: data?.data?.attributes?.country || 'Unknown',
        as_owner: data?.data?.attributes?.as_owner || 'Unknown',
        network: data?.data?.attributes?.network || 'Unknown',
        last_analysis_stats: stats,
        vt_link: `https://www.virustotal.com/gui/ip-address/${ip}`,
        checked_at: new Date().toISOString(),
      };

      if (result.malicious) this.stats.maliciousFound++;
      else this.stats.cleanFound++;

      // Cache the result
      this.cache.set(ip, { result, timestamp: Date.now() });

      console.log(`[VT] IP ${ip}: ${result.malicious ? '🔴 MALICIOUS' : '🟢 CLEAN'} (${totalMalicious}/${totalEngines} engines flagged)`);
      return result;
    } catch (err) {
      this.stats.errors++;
      console.error(`[VT] Error checking IP ${ip}: ${err.message}`);
      return {
        ip,
        status: 'error',
        malicious: false,
        error: err.message,
        checked_at: new Date().toISOString(),
      };
    }
  }

  /**
   * Check file hash via VirusTotal
   */
  async checkHash(hash) {
    if (!this.apiKey) {
      return { hash, status: 'no_api_key', malicious: false };
    }

    try {
      const data = await this._apiRequest(`/files/${hash}`);
      const stats = data?.data?.attributes?.last_analysis_stats || {};
      const totalMalicious = (stats.malicious || 0) + (stats.suspicious || 0);

      return {
        hash,
        status: 'checked',
        malicious: totalMalicious > 2,
        malicious_count: totalMalicious,
        name: data?.data?.attributes?.meaningful_name || 'Unknown',
        type: data?.data?.attributes?.type_description || 'Unknown',
        last_analysis_stats: stats,
        vt_link: `https://www.virustotal.com/gui/file/${hash}`,
      };
    } catch (err) {
      return { hash, status: 'error', malicious: false, error: err.message };
    }
  }

  /**
   * Make API request to VirusTotal
   */
  _apiRequest(endpoint) {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'www.virustotal.com',
        path: `/api/v3${endpoint}`,
        method: 'GET',
        headers: {
          'x-apikey': this.apiKey,
          'Accept': 'application/json',
        },
        timeout: 15000,
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            if (res.statusCode === 200) {
              resolve(JSON.parse(data));
            } else if (res.statusCode === 429) {
              reject(new Error('Rate limit exceeded. Wait 60s.'));
            } else if (res.statusCode === 404) {
              resolve({ data: { attributes: { last_analysis_stats: {} } } });
            } else {
              reject(new Error(`VT API: HTTP ${res.statusCode}`));
            }
          } catch (e) {
            reject(new Error(`VT parse error: ${e.message}`));
          }
        });
      });

      req.on('error', err => reject(err));
      req.on('timeout', () => { req.destroy(); reject(new Error('VT API timeout')); });
      req.end();
    });
  }

  getStats() {
    return { ...this.stats, hasApiKey: !!this.apiKey };
  }
}

module.exports = VirusTotalClient;
