/**
 * SOC-MINI Frontend Application
 * Real-time SCADA Security Operations Dashboard
 */

(function () {
  'use strict';

  // ===== State =====
  const state = {
    ws: null,
    connected: false,
    simulationRunning: false,
    attackRunning: false,
    events: [],
    metrics: {},
    scenarios: [],
    feedFilter: 'all',
    maxFeedItems: 100,
    mitreCounts: {},
    killChainCounts: {
      'Reconnaissance': 0, 'Initial Access': 0, 'Execution': 0,
      'Persistence': 0, 'Lateral Movement': 0, 'Impact': 0,
    },
    severityCounts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    eventTypeCounts: {},
    totalEvents: 0,
  };

  // ===== DOM References =====
  const dom = {};

  function initDOM() {
    // Nav
    dom.navClock = document.getElementById('navClock');
    dom.simIndicator = document.getElementById('simIndicator');
    dom.wsIndicator = document.getElementById('wsIndicator');

    // KPI
    dom.totalEventsValue = document.getElementById('totalEventsValue');
    dom.criticalValue = document.getElementById('criticalValue');
    dom.threatIntelValue = document.getElementById('threatIntelValue');
    dom.wazuhSentValue = document.getElementById('wazuhSentValue');

    // Severity bars
    dom.sevCritical = document.getElementById('sevCritical');
    dom.sevHigh = document.getElementById('sevHigh');
    dom.sevMedium = document.getElementById('sevMedium');
    dom.sevLow = document.getElementById('sevLow');
    dom.sevCriticalCount = document.getElementById('sevCriticalCount');
    dom.sevHighCount = document.getElementById('sevHighCount');
    dom.sevMediumCount = document.getElementById('sevMediumCount');
    dom.sevLowCount = document.getElementById('sevLowCount');

    // Event type counts
    dom.etLogin = document.getElementById('etLogin');
    dom.etPLC = document.getElementById('etPLC');
    dom.etSensor = document.getElementById('etSensor');
    dom.etMalware = document.getElementById('etMalware');
    dom.etLateral = document.getElementById('etLateral');
    dom.etNormal = document.getElementById('etNormal');

    // Top IPs
    dom.topIPsList = document.getElementById('topIPsList');

    // Live feed
    dom.liveFeed = document.getElementById('liveFeed');
    dom.feedFilter = document.getElementById('feedFilter');
    dom.btnClearFeed = document.getElementById('btnClearFeed');

    // Events table
    dom.eventsTableBody = document.getElementById('eventsTableBody');
    dom.eventDetailPanel = document.getElementById('eventDetailPanel');
    dom.eventDetailBody = document.getElementById('eventDetailBody');
    dom.btnCloseDetail = document.getElementById('btnCloseDetail');
    dom.eventSevFilter = document.getElementById('eventSevFilter');
    dom.eventTypeFilter = document.getElementById('eventTypeFilter');
    dom.btnRefreshEvents = document.getElementById('btnRefreshEvents');

    // Attack sim
    dom.btnStartSim = document.getElementById('btnStartSim');
    dom.btnStopSim = document.getElementById('btnStopSim');
    dom.scenarioGrid = document.getElementById('scenarioGrid');

    // SOAR
    dom.soarAlertFeed = document.getElementById('soarAlertFeed');
    dom.pendingApprovalsList = document.getElementById('pendingApprovalsList');
    dom.soarTotalIncidents = document.getElementById('soarTotalIncidents');
    dom.soarCriticalCount = document.getElementById('soarCriticalCount');
    dom.soarMTTD = document.getElementById('soarMTTD');
    dom.soarMTTR = document.getElementById('soarMTTR');
    dom.soarVTScans = document.getElementById('soarVTScans');
    dom.soarShuffleNodes = document.getElementById('soarShuffleNodes');

    // Settings
    dom.wazuhHostInput = document.getElementById('wazuhHostInput');
    dom.wazuhPortInput = document.getElementById('wazuhPortInput');
    dom.btnUpdateWazuh = document.getElementById('btnUpdateWazuh');
    dom.wazuhStatus = document.getElementById('wazuhStatus');
    dom.btnResetAll = document.getElementById('btnResetAll');

    // Toast
    dom.toastContainer = document.getElementById('toastContainer');
  }

  // ===== WebSocket Connection =====
  function connectWebSocket() {
    const wsUrl = `ws://${window.location.hostname}:${window.location.port}`;
    state.ws = new WebSocket(wsUrl);

    state.ws.onopen = () => {
      state.connected = true;
      updateWSIndicator(true);
      showToast('Connected to SOC server', 'success');
    };

    state.ws.onclose = () => {
      state.connected = false;
      updateWSIndicator(false);
      showToast('Disconnected from SOC server. Reconnecting...', 'warning');
      setTimeout(connectWebSocket, 3000);
    };

    state.ws.onerror = () => {
      state.connected = false;
      updateWSIndicator(false);
    };

    state.ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        handleWSMessage(data);
      } catch (e) {
        console.error('WS parse error:', e);
      }
    };
  }

  function handleWSMessage(msg) {
    switch (msg.type) {
      case 'INIT':
        handleInit(msg.data);
        break;
      case 'EVENT':
        handleNewEvent(msg.data);
        break;
      case 'STATUS':
        handleStatusUpdate(msg.data);
        break;
      case 'RESET':
        handleReset();
        break;
    }
  }

  function handleInit(data) {
    state.simulationRunning = data.simulationRunning;
    state.attackRunning = data.attackRunning;
    state.totalEvents = data.eventCount;
    state.scenarios = data.scenarios;

    updateSimIndicator(state.simulationRunning);
    renderScenarios(data.scenarios);

    // Process existing events
    if (data.recentEvents && data.recentEvents.length > 0) {
      for (const event of data.recentEvents) {
        trackEvent(event);
      }
      updateAllDisplays();
    }

    if (data.metrics) {
      updateMetricsFromServer(data.metrics);
    }
  }

  function handleNewEvent(event) {
    trackEvent(event);
    state.totalEvents = event.event_number || state.totalEvents + 1;

    // Update displays
    updateKPIs();
    updateSeverityBars();
    updateEventTypeCounts();
    addToLiveFeed(event);
    updateKillChain(event);
    updateMITRE(event);
    updateTopIPs();

    // Flash effect for critical events
    if (event.threat_severity === 'CRITICAL') {
      flashCritical();
    }
  }

  function handleStatusUpdate(data) {
    if (data.simulationRunning !== undefined) {
      state.simulationRunning = data.simulationRunning;
      updateSimIndicator(data.simulationRunning);
    }
    if (data.attackRunning !== undefined) {
      state.attackRunning = data.attackRunning;
      if (data.attackRunning && data.scenarioId) {
        showToast(`Attack scenario "${data.scenarioId}" launched!`, 'error');
      }
      if (!data.attackRunning) {
        showToast('Attack scenario completed.', 'info');
      }
    }
  }

  function handleReset() {
    state.events = [];
    state.totalEvents = 0;
    state.severityCounts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    state.eventTypeCounts = {};
    state.mitreCounts = {};
    state.killChainCounts = {
      'Reconnaissance': 0, 'Initial Access': 0, 'Execution': 0,
      'Persistence': 0, 'Lateral Movement': 0, 'Impact': 0,
    };
    updateAllDisplays();
    dom.liveFeed.innerHTML = '<div class="empty-state">System reset. Waiting for events...</div>';
    showToast('System reset complete', 'info');
  }

  // ===== Event Tracking =====
  function trackEvent(event) {
    state.events.push(event);
    if (state.events.length > 500) {
      state.events = state.events.slice(-500);
    }

    // Severity
    if (event.threat_severity) {
      state.severityCounts[event.threat_severity] = (state.severityCounts[event.threat_severity] || 0) + 1;
    }

    // Event type
    const et = event.event_type;
    state.eventTypeCounts[et] = (state.eventTypeCounts[et] || 0) + 1;

    // MITRE
    if (event.mitre_id && event.mitre_id !== 'N/A') {
      state.mitreCounts[event.mitre_id] = (state.mitreCounts[event.mitre_id] || 0) + 1;
    }

    // Kill chain
    if (event.attack_stage && event.attack_stage !== 'NONE' && state.killChainCounts.hasOwnProperty(event.attack_stage)) {
      state.killChainCounts[event.attack_stage]++;
    }
  }

  // ===== Display Updates =====
  function updateAllDisplays() {
    updateKPIs();
    updateSeverityBars();
    updateEventTypeCounts();
    updateTopIPs();
    updateKillChainDisplay();
    updateMITREDisplay();
  }

  function updateKPIs() {
    dom.totalEventsValue.textContent = formatNumber(state.totalEvents);
    dom.criticalValue.textContent = formatNumber(state.severityCounts.CRITICAL || 0);

    // CTI matches
    const ctiCount = state.events.filter(e => e.threat_intel_tag === 'THREAT_INTEL_MATCH').length;
    dom.threatIntelValue.textContent = formatNumber(ctiCount);
  }

  function updateMetricsFromServer(metrics) {
    if (metrics.wazuh) {
      dom.wazuhSentValue.textContent = formatNumber(metrics.wazuh.udpSent || 0);
    }
  }

  function updateSeverityBars() {
    const total = Math.max(state.totalEvents, 1);
    const counts = state.severityCounts;

    const maxCount = Math.max(counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW, 1);

    dom.sevCritical.style.width = ((counts.CRITICAL / maxCount) * 100) + '%';
    dom.sevHigh.style.width = ((counts.HIGH / maxCount) * 100) + '%';
    dom.sevMedium.style.width = ((counts.MEDIUM / maxCount) * 100) + '%';
    dom.sevLow.style.width = ((counts.LOW / maxCount) * 100) + '%';

    dom.sevCriticalCount.textContent = counts.CRITICAL || 0;
    dom.sevHighCount.textContent = counts.HIGH || 0;
    dom.sevMediumCount.textContent = counts.MEDIUM || 0;
    dom.sevLowCount.textContent = counts.LOW || 0;
  }

  function updateEventTypeCounts() {
    const c = state.eventTypeCounts;
    dom.etLogin.textContent = c['LOGIN_ATTEMPT'] || 0;
    dom.etPLC.textContent = c['PLC_COMMAND'] || 0;
    dom.etSensor.textContent = (c['SENSOR_ANOMALY'] || 0) + (c['SENSOR_READING'] || 0);
    dom.etMalware.textContent = c['MALWARE_DETECTED'] || 0;
    dom.etLateral.textContent = c['LATERAL_MOVEMENT'] || 0;
    dom.etNormal.textContent = (c['SYSTEM_HEALTH'] || 0) + (c['SENSOR_READING'] || 0);
  }

  function updateTopIPs() {
    const ipCounts = {};
    const maliciousSet = new Set([
      '198.51.100.23', '203.0.113.42', '192.0.2.99', '198.51.100.77', '203.0.113.15'
    ]);

    for (const event of state.events) {
      const ip = event.source_ip;
      if (!ipCounts[ip]) ipCounts[ip] = { count: 0, isMalicious: maliciousSet.has(ip) };
      ipCounts[ip].count++;
    }

    const sorted = Object.entries(ipCounts)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 8);

    if (sorted.length === 0) {
      dom.topIPsList.innerHTML = '<div class="empty-state">No data yet</div>';
      return;
    }

    dom.topIPsList.innerHTML = sorted.map(([ip, data]) => `
      <div class="ip-item ${data.isMalicious ? 'malicious' : ''}">
        <span class="ip-address">${ip}</span>
        <span class="ip-badge ${data.isMalicious ? 'threat' : 'clean'}">${data.isMalicious ? '⚠ THREAT' : 'CLEAN'}</span>
        <span class="ip-count">${data.count}</span>
      </div>
    `).join('');
  }

  function addToLiveFeed(event) {
    // Check filter
    const filter = state.feedFilter;
    if (filter === 'CRITICAL' && event.threat_severity !== 'CRITICAL') return;
    if (filter === 'HIGH' && !['HIGH', 'CRITICAL'].includes(event.threat_severity)) return;
    if (filter === 'attacks' && !['MALWARE_DETECTED', 'SENSOR_ANOMALY', 'LATERAL_MOVEMENT'].includes(event.event_type) && event.status !== 'FAILED' && event.status !== 'UNAUTHORIZED') return;

    const maliciousIPs = new Set([
      '198.51.100.23', '203.0.113.42', '192.0.2.99', '198.51.100.77', '203.0.113.15'
    ]);

    // Remove empty state if present
    const emptyState = dom.liveFeed.querySelector('.empty-state');
    if (emptyState) emptyState.remove();

    const entry = document.createElement('div');
    entry.className = 'feed-entry';
    const time = new Date(event.timestamp).toLocaleTimeString();
    const sevClass = event.threat_severity.toLowerCase();
    const isMalIP = maliciousIPs.has(event.source_ip);

    entry.innerHTML = `
      <span class="feed-time">${time}</span>
      <span class="feed-severity ${sevClass}">${event.threat_severity}</span>
      <span class="feed-type">${event.event_type}</span>
      <span class="feed-desc">${event.description}</span>
      <span class="feed-ip ${isMalIP ? 'malicious' : ''}">${event.source_ip}</span>
    `;

    entry.addEventListener('click', () => showEventDetail(event));

    dom.liveFeed.insertBefore(entry, dom.liveFeed.firstChild);

    // Trim feed
    while (dom.liveFeed.children.length > state.maxFeedItems) {
      dom.liveFeed.removeChild(dom.liveFeed.lastChild);
    }
  }

  function updateKillChain(event) {
    updateKillChainDisplay();
  }

  function updateKillChainDisplay() {
    const stages = document.querySelectorAll('.kc-stage');
    stages.forEach(stage => {
      const name = stage.dataset.stage;
      const count = state.killChainCounts[name] || 0;
      const countEl = stage.querySelector('.kc-count');
      if (countEl) countEl.textContent = count;
      if (count > 0) {
        stage.classList.add('active');
      } else {
        stage.classList.remove('active');
      }
    });
  }

  function updateMITRE(event) {
    updateMITREDisplay();
  }

  function updateMITREDisplay() {
    const maxCount = Math.max(...Object.values(state.mitreCounts), 1);

    document.querySelectorAll('.mitre-technique').forEach(card => {
      const id = card.dataset.mitre;
      const count = state.mitreCounts[id] || 0;
      const countEl = card.querySelector('.mt-count');
      const barFill = card.querySelector('.mt-bar-fill');

      if (countEl) countEl.textContent = count;
      if (barFill) barFill.style.width = ((count / maxCount) * 100) + '%';

      if (count > 0) {
        card.classList.add('hit');
      } else {
        card.classList.remove('hit');
      }
    });
  }

  // ===== Event Detail Panel =====
  function showEventDetail(event) {
    const fields = [
      { label: 'Event ID', value: event.event_id },
      { label: 'Timestamp', value: event.timestamp },
      { label: 'Event Type', value: event.event_type },
      { label: 'Description', value: event.description },
      { label: 'Source IP', value: event.source_ip },
      { label: 'Destination IP', value: event.destination_ip },
      { label: 'Username', value: event.username },
      { label: 'Status', value: event.status },
      { label: 'Severity', value: event.threat_severity },
      { label: 'Risk Score', value: `${event.risk_score}/100` },
      { label: 'IoC Type', value: event.ioc_type },
      { label: 'IoA Type', value: event.ioa_type },
      { label: 'Attack Stage', value: event.attack_stage },
      { label: 'MITRE ID', value: event.mitre_id },
      { label: 'MITRE Technique', value: event.mitre_technique },
      { label: 'MITRE Tactic', value: event.mitre_tactic },
      { label: 'CTI Tag', value: event.threat_intel_tag },
      { label: 'PLC ID', value: event.plc_id },
      { label: 'PLC Command', value: event.plc_command },
      { label: 'Sensor Type', value: event.sensor_type },
      { label: 'Sensor Value', value: event.sensor_value },
    ];

    dom.eventDetailBody.innerHTML = fields
      .filter(f => f.value && f.value !== 'null' && f.value !== null)
      .map(f => `
        <div class="detail-field">
          <div class="detail-field-label">${f.label}</div>
          <div class="detail-field-value">${f.value}</div>
        </div>
      `).join('');

    dom.eventDetailPanel.classList.add('open');
  }

  // ===== Events Table =====
  function refreshEventsTable() {
    const sevFilter = dom.eventSevFilter.value;
    const typeFilter = dom.eventTypeFilter.value;

    let filtered = [...state.events];
    if (sevFilter) filtered = filtered.filter(e => e.threat_severity === sevFilter);
    if (typeFilter) filtered = filtered.filter(e => e.event_type === typeFilter);

    const display = filtered.slice(-100).reverse();

    dom.eventsTableBody.innerHTML = display.map(event => {
      const time = new Date(event.timestamp).toLocaleTimeString();
      const sevClass = event.threat_severity.toLowerCase();
      const ctiClass = event.threat_intel_tag === 'THREAT_INTEL_MATCH' ? 'match'
        : event.threat_intel_tag === 'SUSPICIOUS_IP' ? 'suspicious' : 'clean';
      const rowClass = event.threat_severity === 'CRITICAL' ? 'critical-row' : '';

      return `
        <tr class="${rowClass}" data-id="${event.event_id}">
          <td>${event.event_number || '-'}</td>
          <td>${time}</td>
          <td><span class="sev-badge ${sevClass}">${event.threat_severity}</span></td>
          <td>${event.event_type}</td>
          <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis">${event.description}</td>
          <td>${event.source_ip}</td>
          <td>${event.mitre_id}</td>
          <td>${event.ioc_type !== 'NONE' ? event.ioc_type : '-'}</td>
          <td><span class="cti-badge ${ctiClass}">${event.threat_intel_tag}</span></td>
          <td>${event.risk_score}</td>
        </tr>
      `;
    }).join('');

    // Add click handlers
    dom.eventsTableBody.querySelectorAll('tr').forEach(row => {
      row.addEventListener('click', () => {
        const eventId = row.dataset.id;
        const event = state.events.find(e => e.event_id === eventId);
        if (event) showEventDetail(event);
      });
    });
  }

  // ===== Scenario Rendering =====
  function renderScenarios(scenarios) {
    if (!scenarios || scenarios.length === 0) return;

    dom.scenarioGrid.innerHTML = scenarios.map(s => `
      <div class="scenario-card" data-scenario="${s.id}">
        <div class="scenario-name">${s.name}</div>
        <div class="scenario-desc">${s.description}</div>
        <div class="scenario-stages">
          ${s.stages.map(st => `<span class="stage-tag">${st}</span>`).join('')}
        </div>
        <button class="btn btn-attack" onclick="launchAttack('${s.id}')">
          ⚡ Launch Attack
        </button>
      </div>
    `).join('');
  }

  // ===== SOAR Dashboard (Real Shuffle Alerts) =====
  async function refreshSOARData() {
    try {
      const [shuffleRes, statsRes] = await Promise.all([
        fetch('/api/shuffle/alerts').then(r => r.json()).then(d => d.alerts || []).catch(() => []),
        fetch('/api/soar/stats').then(r => r.json()).catch(() => ({})),
      ]);

      // Update KPIs from stats
      const stats = statsRes || {};
      if (dom.soarTotalIncidents) dom.soarTotalIncidents.textContent = shuffleRes.length || 0;
      if (dom.soarCriticalCount) dom.soarCriticalCount.textContent = shuffleRes.filter(a => a.severity === 'CRITICAL').length;
      if (dom.soarMTTD) dom.soarMTTD.textContent = (stats.avgMTTD || 0) + 's';
      if (dom.soarMTTR) dom.soarMTTR.textContent = (stats.avgMTTR || 0) + 's';
      if (dom.soarVTScans) dom.soarVTScans.textContent = shuffleRes.filter(a => a.vt?.status == 200).length;
      if (dom.soarShuffleNodes) {
        const avgNodes = shuffleRes.length > 0 ? Math.round(shuffleRes.reduce((s, a) => s + (a.nodes_completed || 0), 0) / shuffleRes.length) : 0;
        dom.soarShuffleNodes.textContent = avgNodes;
      }

      // Render Shuffle alerts feed
      const alerts = Array.isArray(shuffleRes) ? shuffleRes : [];
      if (alerts.length > 0 && dom.soarAlertFeed) {
        dom.soarAlertFeed.innerHTML = alerts.slice(0, 20).map(alert => {
          const sevClass = (alert.severity || 'medium').toLowerCase();
          const sevIcon = alert.severity === 'CRITICAL' ? '🔴' : alert.severity === 'HIGH' ? '🟠' : '🟡';
          const wfStatus = alert.workflow_status === 'SUCCESS' ? '✅' : alert.workflow_status === 'EXECUTING' ? '⏳' : '🔄';
          const vtMal = parseInt(alert.vt?.malicious) || 0;
          const vtColor = vtMal > 0 ? 'var(--severity-critical)' : 'var(--accent-green)';
          const vtHasData = alert.vt?.total > 0;
          const vtLabel = vtMal > 0 ? `🔴 ${vtMal}/${alert.vt.total} MALICIOUS` : vtHasData ? `🟢 CLEAN (${alert.vt.total} engines)` : '⚪ N/A';
          const mispColor = alert.misp?.found ? 'var(--severity-critical)' : 'var(--text-muted)';
          const mispBlocked = alert.misp?.is_blocked;
          const mispLabel = mispBlocked
            ? `🚫 BLOCKED (${alert.misp.count} IOCs)`
            : alert.misp?.found ? `🔴 ${alert.misp.count} IOCs` : vtHasData ? '⚪ No match' : '⚪ N/A';
          const vtRepInfo = alert.vt?.reputation !== undefined && vtHasData ? ` | Rep: ${alert.vt.reputation}` : '';
          const vtCountryInfo = alert.vt?.country ? ` | 🌍 ${alert.vt.country}` : '';
          const timeStr = alert.started_at ? new Date(alert.started_at).toLocaleTimeString() : (alert.received_at ? new Date(alert.received_at).toLocaleTimeString() : '');
          const sourceLabel = alert.source === 'SHUFFLE_CLOUD' ? '☁️ Shuffle Cloud' : alert.source === 'LOCAL_SOAR' ? '🖥️ Local SOAR' : '📡 Webhook';
          return `
            <div class="feed-item ${sevClass}" style="border-left:3px solid var(--severity-${sevClass});padding:0.6rem 0.8rem;margin-bottom:0.5rem;background:rgba(0,0,0,0.2);border-radius:6px;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.3rem;">
                <span style="font-weight:700;color:var(--severity-${sevClass});">${sevIcon} ${alert.severity} — ${alert.classification}</span>
                <span style="font-size:0.68rem;color:var(--text-muted);">
                  ${wfStatus} ${sourceLabel} | ${alert.id} | ${timeStr}
                </span>
              </div>
              <div style="font-size:0.78rem;color:var(--text-secondary);margin-bottom:0.3rem;">
                🌐 <strong>${alert.source_ip}</strong> — ${alert.description || alert.event_type || ''}
              </div>
              <div style="font-size:0.7rem;display:flex;gap:14px;flex-wrap:wrap;">
                <span style="color:${vtColor};">VT: ${vtLabel}${vtRepInfo}${vtCountryInfo}</span>
                <span style="color:${mispColor};">MISP: ${mispLabel}</span>${mispBlocked ? '<span style="background:rgba(255,59,48,0.2);color:#ff3b30;padding:1px 6px;border-radius:3px;font-size:0.65rem;font-weight:700;margin-left:4px;">⛔ IP BLOCKED</span>' : ''}
                <span style="color:var(--accent-blue);">MITRE: ${alert.mitre_id || 'N/A'}</span>
                <span style="color:var(--text-muted);">Nodes: ${alert.nodes_completed || '?'}</span>
              </div>
            </div>
          `;
        }).join('');
      } else if (dom.soarAlertFeed) {
        dom.soarAlertFeed.innerHTML = '<div class="empty-state">No Shuffle alerts yet. Launch an attack to trigger the pipeline.</div>';
      }

      // === Human-in-the-Loop: Generate approvals from CRITICAL alerts ===
      const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL');
      const approvalDiv = document.getElementById('pendingApprovalsList');
      if (criticalAlerts.length > 0 && approvalDiv) {
        const criticalActions = [
          { action: 'ISOLATE_PLC', desc: 'Disconnect PLC from OT network to prevent further C2 commands' },
          { action: 'REVOKE_CREDENTIALS', desc: 'Revoke compromised user credentials in Active Directory' },
          { action: 'LOCK_SCADA_SERVER', desc: 'Lock SCADA HMI server to prevent unauthorized access' },
        ];
        approvalDiv.innerHTML = criticalAlerts.slice(0, 5).map(alert => {
          const approvedActions = window._approvedActions || {};
          return `
            <div style="background:rgba(255,59,48,0.06);border:1px solid rgba(255,59,48,0.15);border-radius:8px;padding:0.8rem;margin-bottom:0.6rem;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                <span style="font-weight:700;color:var(--severity-critical);">🔴 ${alert.classification}</span>
                <span style="font-size:0.7rem;color:var(--text-muted);">${alert.id} | ${alert.source_ip}</span>
              </div>
              ${criticalActions.map(ca => {
            const key = alert.id + '_' + ca.action;
            const resolved = approvedActions[key];
            if (resolved) {
              return `
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:0.4rem 0.6rem;margin:0.3rem 0;background:rgba(0,0,0,0.15);border-radius:6px;">
                      <div style="flex:1;">
                        <div style="font-size:0.8rem;color:var(--text-primary);font-weight:600;">${ca.action}</div>
                        <div style="font-size:0.7rem;color:var(--text-muted);">${ca.desc}</div>
                      </div>
                      <span style="font-size:0.72rem;padding:3px 10px;border-radius:10px;background:${resolved === 'APPROVED' ? 'rgba(0,245,160,0.15)' : 'rgba(255,59,48,0.15)'};color:${resolved === 'APPROVED' ? 'var(--accent-green)' : 'var(--severity-critical)'};font-weight:600;">
                        ${resolved === 'APPROVED' ? '✅ APPROVED' : '❌ DENIED'}
                      </span>
                    </div>`;
            }
            return `
                  <div style="display:flex;justify-content:space-between;align-items:center;padding:0.4rem 0.6rem;margin:0.3rem 0;background:rgba(0,0,0,0.2);border-radius:6px;">
                    <div style="flex:1;">
                      <div style="font-size:0.8rem;color:var(--text-primary);font-weight:600;">${ca.action}</div>
                      <div style="font-size:0.7rem;color:var(--text-muted);">${ca.desc}</div>
                    </div>
                    <div style="display:flex;gap:6px;margin-left:10px;">
                      <button onclick="approveAction('${alert.id}','${ca.action}')" style="padding:4px 14px;border:none;border-radius:4px;background:var(--accent-green);color:#0a0e17;font-size:0.72rem;font-weight:700;cursor:pointer;transition:opacity 0.2s;" onmouseover="this.style.opacity='0.8'" onmouseout="this.style.opacity='1'">✓ Approve</button>
                      <button onclick="denyAction('${alert.id}','${ca.action}')" style="padding:4px 14px;border:none;border-radius:4px;background:var(--severity-critical);color:white;font-size:0.72rem;font-weight:700;cursor:pointer;transition:opacity 0.2s;" onmouseover="this.style.opacity='0.8'" onmouseout="this.style.opacity='1'">✕ Deny</button>
                    </div>
                  </div>`;
          }).join('')}
            </div>`;
        }).join('');
      } else if (approvalDiv) {
        approvalDiv.innerHTML = '<div class="empty-state">No critical actions pending. CRITICAL incidents will appear here for analyst review.</div>';
      }

    } catch (err) {
      console.error('SOAR refresh error:', err);
    }
  }

  // === Human-in-the-Loop: Approve/Deny functions ===
  window._approvedActions = {};

  window.approveAction = function (alertId, action) {
    window._approvedActions[alertId + '_' + action] = 'APPROVED';
    showToast(`✅ ${action} approved by SOC Analyst`, 'success');
    refreshSOARData();
  };

  window.denyAction = function (alertId, action) {
    window._approvedActions[alertId + '_' + action] = 'DENIED';
    showToast(`❌ ${action} denied — analyst review: action not required`, 'warning');
    refreshSOARData();
  };

  // Make refreshSOAR available globally (called from onclick)
  window.refreshSOAR = refreshSOARData;

  // === Custom Attack Demo — Workflow Visualization ===
  window.launchCustomAttack = async function () {
    const ip = document.getElementById('customAttackIP')?.value?.trim();
    const user = document.getElementById('customAttackUser')?.value || 'root';
    const tracker = document.getElementById('workflowTracker');
    const stepsDiv = document.getElementById('workflowSteps');
    const resultDiv = document.getElementById('workflowResult');
    const btn = document.getElementById('btnCustomAttack');

    if (!ip) { showToast('Enter an attacker IP address', 'error'); return; }

    // Show tracker & disable button
    tracker.style.display = 'block';
    stepsDiv.innerHTML = '';
    resultDiv.innerHTML = '';
    btn.disabled = true;
    btn.textContent = '⏳ Executing pipeline...';

    // Show animated "searching" steps
    const stepNames = [
      { icon: '🎯', name: 'Generating Attack Event', color: 'var(--severity-critical)' },
      { icon: '🔍', name: 'Enriching with CTI + MITRE', color: 'var(--accent-cyan)' },
      { icon: '🛡️', name: 'VirusTotal IP Scan (94 engines)', color: 'var(--accent-green)' },
      { icon: '🔎', name: 'MISP IOC Database Search', color: 'var(--accent-orange)' },
      { icon: '⚖️', name: 'SOAR Classification & Incident', color: '#af52de' },
      { icon: '☁️', name: 'Forward to Shuffle Cloud', color: 'var(--accent-blue)' },
      { icon: '📤', name: 'Push Alert to MISP', color: 'var(--accent-green)' },
    ];

    // Animate steps appearing
    for (let i = 0; i < stepNames.length; i++) {
      const s = stepNames[i];
      stepsDiv.innerHTML += `
        <div id="wfStep${i + 1}" style="display:flex;align-items:center;gap:10px;padding:6px 10px;margin:3px 0;border-radius:6px;background:rgba(255,255,255,0.03);transition:all 0.3s;">
          <span style="font-size:1.1rem;">${s.icon}</span>
          <span style="flex:1;font-size:0.82rem;color:var(--text-muted);">Step ${i + 1}: ${s.name}</span>
          <span id="wfStatus${i + 1}" style="font-size:0.75rem;color:var(--text-muted);">⏳ waiting...</span>
        </div>`;
      await new Promise(r => setTimeout(r, 100));
    }

    try {
      const res = await fetch('/api/attack/custom-demo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attacker_ip: ip, username: user }),
      });
      const data = await res.json();

      if (data.error) { showToast('Attack failed: ' + data.error, 'error'); return; }

      // Animate results step by step
      for (const step of data.steps) {
        await new Promise(r => setTimeout(r, 400));
        const statusEl = document.getElementById(`wfStatus${step.step}`);
        const stepEl = document.getElementById(`wfStep${step.step}`);
        if (statusEl) {
          statusEl.textContent = `${step.status} ${step.time}ms`;
          statusEl.style.color = step.status === '✅' ? 'var(--accent-green)' : step.status === '⏭️' ? 'var(--text-muted)' : 'var(--accent-orange)';
        }
        if (stepEl) {
          stepEl.style.background = step.status === '✅' ? 'rgba(0,245,160,0.06)' : 'rgba(255,149,0,0.06)';
          // Add detail line
          stepEl.innerHTML += `<div style="width:100%;font-size:0.72rem;color:var(--text-secondary);margin-top:2px;padding-left:30px;">${step.detail}</div>`;
        }
      }

      // Final result summary
      await new Promise(r => setTimeout(r, 500));
      const sevColor = data.severity === 'CRITICAL' ? 'var(--severity-critical)' : data.severity === 'HIGH' ? 'var(--severity-high)' : 'var(--accent-green)';
      resultDiv.innerHTML = `
        <div style="background:rgba(0,245,160,0.06);border:1px solid rgba(0,245,160,0.2);border-radius:8px;padding:1rem;margin-top:0.5rem;">
          <div style="font-weight:700;color:var(--accent-green);margin-bottom:0.5rem;">✅ Pipeline Complete — ${data.total_time_ms}ms</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:0.8rem;">
            <div>🎯 <strong>Attacker:</strong> ${data.attacker_ip}</div>
            <div>👤 <strong>Username:</strong> ${data.username}</div>
            <div>🔴 <strong>Severity:</strong> <span style="color:${sevColor};font-weight:700;">${data.severity}</span></div>
            <div>📋 <strong>Classification:</strong> ${data.classification}</div>
            <div>🆔 <strong>Incident:</strong> <span style="font-family:monospace;">${data.incident_id || 'N/A'}</span></div>
            <div>⏱️ <strong>Total Time:</strong> ${data.total_time_ms}ms</div>
          </div>
          <div style="margin-top:0.6rem;font-size:0.75rem;color:var(--text-muted);">
            💡 Switch to <strong>SOAR Alerts</strong> tab and click <strong>Refresh</strong> to see this alert in the Shuffle Cloud feed.
          </div>
        </div>`;

      showToast(`🚨 Attack from ${ip} → ${data.severity} incident created in ${data.total_time_ms}ms`, data.severity === 'CRITICAL' ? 'error' : 'warning');

    } catch (err) {
      showToast('Custom attack failed: ' + err.message, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = '🚀 Launch Attack & Show Workflow';
    }
  };

  // === Generate 5 Brute Force Logs ===
  window.launchBruteForce5 = async function () {
    const ip = document.getElementById('customAttackIP')?.value?.trim();
    const user = document.getElementById('customAttackUser')?.value || 'root';
    const btn = document.getElementById('btnBruteForce5');
    const progress = document.getElementById('bruteForceProgress');

    if (!ip) { showToast('Enter an attacker IP first', 'error'); return; }

    btn.disabled = true;
    btn.textContent = '⏳ Generating...';
    progress.style.display = 'block';
    progress.innerHTML = `
      <div style="font-weight:700;color:var(--accent-orange);margin-bottom:0.5rem;font-size:0.85rem;">
        🔥 Brute Force Simulation — 5 Login Attempts from <span style="color:var(--severity-critical);font-family:monospace;">${ip}</span>
      </div>
      <div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:6px;">Auto-block threshold: <strong>3 attempts</strong>. IP will be blocked in MISP after 3rd failed login.</div>
      <div id="bfSteps"></div>`;

    const stepsDiv = document.getElementById('bfSteps');
    const usernames = [user, 'admin', 'operator1', 'scada_admin', 'root'];

    for (let i = 0; i < 5; i++) {
      const attemptUser = usernames[i] || user;
      const stepEl = document.createElement('div');
      stepEl.style.cssText = 'display:flex;align-items:center;gap:10px;padding:6px 10px;margin:3px 0;border-radius:6px;background:rgba(255,255,255,0.03);transition:all 0.3s;';
      stepEl.innerHTML = `
        <span style="font-size:0.85rem;">⏳</span>
        <span style="flex:1;font-size:0.8rem;color:var(--text-muted);">Attempt #${i + 1} — user: <strong>${attemptUser}</strong></span>
        <span style="font-size:0.72rem;color:var(--text-muted);">sending...</span>`;
      stepsDiv.appendChild(stepEl);

      try {
        const res = await fetch('/api/attack/custom-demo', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ attacker_ip: ip, username: attemptUser }),
        });
        const data = await res.json();
        const mispStep = data.steps?.find(s => s.name === 'MISP_IOC_SEARCH');
        const mispInfo = mispStep ? mispStep.detail : '';

        // Check if auto-blocked
        const wasBlocked = data.steps?.some(s => s.detail && s.detail.includes('auto-blocked'));
        const isAlreadyBlocked = data.steps?.some(s => s.detail && s.detail.includes('already blocked'));

        let statusIcon, statusText, statusColor;
        if (wasBlocked) {
          statusIcon = '🚫';
          statusText = 'AUTO-BLOCKED IN MISP!';
          statusColor = '#ff3b30';
          stepEl.style.background = 'rgba(255,59,48,0.12)';
          stepEl.style.border = '1px solid rgba(255,59,48,0.3)';
        } else if (isAlreadyBlocked) {
          statusIcon = '⛔';
          statusText = 'Already blocked';
          statusColor = '#ff9500';
        } else if (i < 2) {
          statusIcon = '⚠️';
          statusText = `${i + 1}/3 — ${2 - i} more to block`;
          statusColor = '#ffd60a';
        } else {
          statusIcon = '🔴';
          statusText = `${data.severity} — ${mispInfo.substring(0, 40)}`;
          statusColor = 'var(--text-muted)';
        }

        stepEl.innerHTML = `
          <span style="font-size:0.85rem;">${statusIcon}</span>
          <span style="flex:1;font-size:0.8rem;color:var(--text-primary);">
            Attempt #${i + 1} — <strong>${attemptUser}</strong>
            <span style="font-size:0.7rem;color:var(--text-muted);margin-left:6px;">VT: ${data.steps?.find(s => s.name === 'VIRUSTOTAL_SCAN')?.data?.malicious_count || 0}/${data.steps?.find(s => s.name === 'VIRUSTOTAL_SCAN')?.data?.total_engines || 94}</span>
          </span>
          <span style="font-size:0.72rem;color:${statusColor};font-weight:600;">${statusText}</span>`;

      } catch (err) {
        stepEl.innerHTML = `
          <span style="font-size:0.85rem;">❌</span>
          <span style="flex:1;font-size:0.8rem;color:var(--severity-critical);">Attempt #${i + 1} failed: ${err.message}</span>`;
      }

      // Brief pause between attempts
      if (i < 4) await new Promise(r => setTimeout(r, 800));
    }

    // Final summary
    const blockedRes = await fetch('/api/misp/blocked-ips');
    const blockedData = await blockedRes.json();
    const isBlocked = blockedData.blocked_ips?.some(b => b.ip === ip);

    stepsDiv.innerHTML += `
      <div style="margin-top:10px;padding:8px 12px;border-radius:6px;background:${isBlocked ? 'rgba(255,59,48,0.1)' : 'rgba(0,245,160,0.1)'};border:1px solid ${isBlocked ? 'rgba(255,59,48,0.3)' : 'rgba(0,245,160,0.3)'};">
        <span style="font-size:0.85rem;font-weight:700;color:${isBlocked ? '#ff3b30' : '#00f5a0'};">
          ${isBlocked ? '🚫 RESULT: IP ' + ip + ' is now BLOCKED in MISP threat intel blocklist' : '✅ RESULT: IP ' + ip + ' was already blocked or not enough attempts'}
        </span>
      </div>`;

    btn.disabled = false;
    btn.textContent = '🔥 Generate 5 Brute Force Logs';
    showToast(isBlocked ? `🚫 ${ip} auto-blocked after brute force simulation!` : `Brute force simulation complete`, isBlocked ? 'warning' : 'success');
    refreshBlockedIPs();
    setTimeout(() => refreshSOARData(), 2000);
  };

  // === MISP Blocked IPs Functions ===
  window.blockIPFromDashboard = async function () {
    const ip = document.getElementById('blockIPInput')?.value?.trim();
    const reason = document.getElementById('blockIPReason')?.value?.trim() || 'Blocked via SOC Dashboard';
    const btn = document.getElementById('btnBlockIP');
    if (!ip) { showToast('Enter an IP address to block', 'error'); return; }

    btn.disabled = true;
    btn.textContent = '⏳ Blocking...';
    try {
      const res = await fetch('/api/misp/block-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason, analyst: 'SOC Analyst' }),
      });
      const data = await res.json();
      if (data.success) {
        showToast(`🚫 IP ${ip} blocked in MISP (Event #${data.event_id})`, 'success');
        document.getElementById('blockIPInput').value = '';
        document.getElementById('blockIPReason').value = '';
        refreshBlockedIPs();
      } else {
        showToast('Block failed: ' + (data.error || 'Unknown error'), 'error');
      }
    } catch (err) {
      showToast('Block failed: ' + err.message, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = '🚫 Block IP in MISP';
    }
  };

  window.refreshBlockedIPs = async function () {
    const container = document.getElementById('blockedIPsList');
    if (!container) return;

    container.innerHTML = '<div class="empty-state">⏳ Fetching from MISP...</div>';
    try {
      const res = await fetch('/api/misp/blocked-ips');
      const data = await res.json();
      const ips = data.blocked_ips || [];

      if (ips.length === 0) {
        container.innerHTML = '<div class="empty-state">No blocked IPs in MISP yet. Use the form above to block an IP.</div>';
        return;
      }

      // Deduplicate by IP
      const seen = new Set();
      const unique = ips.filter(i => { if (seen.has(i.ip)) return false; seen.add(i.ip); return true; });

      container.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px;">
          ${unique.map(entry => {
        const time = entry.timestamp ? new Date(entry.timestamp).toLocaleString() : 'Unknown';
        return `
              <div style="display:flex;align-items:center;gap:10px;padding:8px 12px;background:rgba(255,59,48,0.06);border:1px solid rgba(255,59,48,0.15);border-radius:8px;">
                <span style="font-size:1.2rem;">🚫</span>
                <div style="flex:1;min-width:0;">
                  <div style="font-family:'JetBrains Mono',monospace;font-weight:700;color:var(--severity-critical);font-size:0.85rem;">${entry.ip}</div>
                  <div style="font-size:0.7rem;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${entry.comment}">${entry.comment || 'Blocked'}</div>
                  <div style="font-size:0.65rem;color:var(--text-muted);">🕐 ${time} | MISP Event #${entry.event_id}</div>
                </div>
                <span style="font-size:0.7rem;padding:2px 8px;background:rgba(255,59,48,0.15);border-radius:4px;color:var(--severity-critical);font-weight:600;">BLOCKED</span>
              </div>`;
      }).join('')}
        </div>
        <div style="margin-top:8px;font-size:0.72rem;color:var(--text-muted);text-align:right;">
          Total: <strong>${unique.length}</strong> blocked IPs from MISP | 
          <span style="color:var(--accent-green);">✅ IDS/Firewall sync active</span>
        </div>`;

    } catch (err) {
      container.innerHTML = `<div class="empty-state" style="color:var(--severity-critical);">Error: ${err.message}</div>`;
    }
  };

  // Load blocked IPs when SOAR tab is opened
  const origTabHandler = document.querySelectorAll('.tab-btn');
  origTabHandler.forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.dataset.tab === 'soar') {
        setTimeout(() => refreshBlockedIPs(), 500);
      }
    });
  });

  // === MISP Blocked IPs Functions ===
  window.blockIPFromDashboard = async function () {
    const ip = document.getElementById('blockIPInput')?.value?.trim();
    const reason = document.getElementById('blockIPReason')?.value?.trim() || 'Blocked via SOC Dashboard';
    const btn = document.getElementById('btnBlockIP');
    if (!ip) { showToast('Enter an IP address to block', 'error'); return; }

    btn.disabled = true;
    btn.textContent = '⏳ Blocking...';
    try {
      const res = await fetch('/api/misp/block-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason, analyst: 'SOC Analyst' }),
      });
      const data = await res.json();
      if (data.success) {
        showToast(`🚫 IP ${ip} blocked in MISP (Event #${data.event_id})`, 'success');
        document.getElementById('blockIPInput').value = '';
        document.getElementById('blockIPReason').value = '';
        refreshBlockedIPs();
      } else {
        showToast('Block failed: ' + (data.error || 'Unknown error'), 'error');
      }
    } catch (err) {
      showToast('Block failed: ' + err.message, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = '🚫 Block IP in MISP';
    }
  };

  window.refreshBlockedIPs = async function () {
    const container = document.getElementById('blockedIPsList');
    if (!container) return;

    container.innerHTML = '<div class="empty-state">⏳ Fetching from MISP...</div>';
    try {
      const res = await fetch('/api/misp/blocked-ips');
      const data = await res.json();
      const ips = data.blocked_ips || [];

      if (ips.length === 0) {
        container.innerHTML = '<div class="empty-state">No blocked IPs in MISP yet. Use the form above to block an IP.</div>';
        return;
      }

      // Deduplicate by IP
      const seen = new Set();
      const unique = ips.filter(i => { if (seen.has(i.ip)) return false; seen.add(i.ip); return true; });

      container.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px;">
          ${unique.map(entry => {
        const time = entry.timestamp ? new Date(entry.timestamp).toLocaleString() : 'Unknown';
        return `
              <div style="display:flex;align-items:center;gap:10px;padding:8px 12px;background:rgba(255,59,48,0.06);border:1px solid rgba(255,59,48,0.15);border-radius:8px;">
                <span style="font-size:1.2rem;">🚫</span>
                <div style="flex:1;min-width:0;">
                  <div style="font-family:'JetBrains Mono',monospace;font-weight:700;color:var(--severity-critical);font-size:0.85rem;">${entry.ip}</div>
                  <div style="font-size:0.7rem;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${entry.comment}">${entry.comment || 'Blocked'}</div>
                  <div style="font-size:0.65rem;color:var(--text-muted);">🕐 ${time} | MISP Event #${entry.event_id}</div>
                </div>
                <span style="font-size:0.7rem;padding:2px 8px;background:rgba(255,59,48,0.15);border-radius:4px;color:var(--severity-critical);font-weight:600;">BLOCKED</span>
              </div>`;
      }).join('')}
        </div>
        <div style="margin-top:8px;font-size:0.72rem;color:var(--text-muted);text-align:right;">
          Total: <strong>${unique.length}</strong> blocked IPs from MISP |
          <span style="color:var(--accent-green);">✅ IDS/Firewall sync active</span>
        </div>`;

    } catch (err) {
      container.innerHTML = `<div class="empty-state" style="color:var(--severity-critical);">Error: ${err.message}</div>`;
    }
  };

  // Auto-load blocked IPs when SOAR tab is opened
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.dataset.tab === 'soar') {
        setTimeout(() => refreshBlockedIPs(), 500);
      }
    });
  });

  // ===== API Calls =====
  async function startSimulation() {
    try {
      await fetch('/api/simulation/start', { method: 'POST' });
      showToast('Normal SCADA simulation started', 'success');
    } catch (e) {
      showToast('Failed to start simulation', 'error');
    }
  }

  async function stopSimulation() {
    try {
      await fetch('/api/simulation/stop', { method: 'POST' });
      showToast('Simulation stopped', 'info');
    } catch (e) {
      showToast('Failed to stop simulation', 'error');
    }
  }

  window.launchAttack = async function (scenarioId) {
    try {
      await fetch('/api/attack/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioId }),
      });
    } catch (e) {
      showToast('Failed to launch attack', 'error');
    }
  };

  async function updateWazuhConfig() {
    try {
      const host = dom.wazuhHostInput.value;
      const port = parseInt(dom.wazuhPortInput.value);
      const res = await fetch('/api/wazuh/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, port }),
      });
      const data = await res.json();
      dom.wazuhStatus.innerHTML = `<span style="color: var(--accent-green)">✓ Updated to ${data.host}:${data.port}</span>`;
      showToast(`Wazuh target updated: ${data.host}:${data.port}`, 'success');
    } catch (e) {
      dom.wazuhStatus.innerHTML = `<span style="color: var(--severity-critical)">✗ Update failed</span>`;
      showToast('Failed to update Wazuh config', 'error');
    }
  }

  async function resetAll() {
    try {
      await fetch('/api/reset', { method: 'POST' });
    } catch (e) {
      showToast('Failed to reset', 'error');
    }
  }

  async function fetchMetrics() {
    try {
      const res = await fetch('/api/metrics');
      const data = await res.json();
      if (data.wazuh) {
        dom.wazuhSentValue.textContent = formatNumber(data.wazuh.udpSent || 0);
      }
    } catch (e) {
      // Silently fail
    }
  }

  // ===== UI Helpers =====
  function updateSimIndicator(running) {
    const dot = dom.simIndicator.querySelector('.indicator-dot');
    if (running) {
      dot.className = 'indicator-dot active';
    } else {
      dot.className = 'indicator-dot offline';
    }
  }

  function updateWSIndicator(connected) {
    const dot = dom.wsIndicator.querySelector('.indicator-dot');
    if (connected) {
      dot.className = 'indicator-dot active';
    } else {
      dot.className = 'indicator-dot offline';
    }
  }

  function flashCritical() {
    document.body.style.boxShadow = 'inset 0 0 100px rgba(255, 59, 48, 0.1)';
    setTimeout(() => {
      document.body.style.boxShadow = 'none';
    }, 500);
  }

  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    dom.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.animation = 'toastOut 0.3s ease forwards';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  function formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return n.toString();
  }

  function updateClock() {
    dom.navClock.textContent = new Date().toLocaleTimeString();
  }

  // ===== Tab Navigation =====
  function initTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tabId = btn.dataset.tab;

        // Update active tab button
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        // Show corresponding tab content
        document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
        const tabContent = document.getElementById(tabId + 'Tab');
        if (tabContent) tabContent.classList.add('active');

        // Refresh content when switching tabs
        if (tabId === 'events') refreshEventsTable();
        if (tabId === 'soar') refreshSOARData();
      });
    });
  }

  // ===== Event Listeners =====
  function initEventListeners() {
    // Simulation controls
    dom.btnStartSim.addEventListener('click', startSimulation);
    dom.btnStopSim.addEventListener('click', stopSimulation);

    // Feed controls
    dom.feedFilter.addEventListener('change', (e) => {
      state.feedFilter = e.target.value;
    });
    dom.btnClearFeed.addEventListener('click', () => {
      dom.liveFeed.innerHTML = '<div class="empty-state">Feed cleared. New events will appear here.</div>';
    });

    // Event detail close
    dom.btnCloseDetail.addEventListener('click', () => {
      dom.eventDetailPanel.classList.remove('open');
    });

    // Event filters
    dom.btnRefreshEvents.addEventListener('click', refreshEventsTable);
    dom.eventSevFilter.addEventListener('change', refreshEventsTable);
    dom.eventTypeFilter.addEventListener('change', refreshEventsTable);

    // SOAR auto-refresh
    setInterval(refreshSOARData, 5000);

    // Settings
    dom.btnUpdateWazuh.addEventListener('click', updateWazuhConfig);
    dom.btnResetAll.addEventListener('click', resetAll);
  }

  // ===== Initialize =====
  function init() {
    initDOM();
    initTabs();
    initEventListeners();
    connectWebSocket();

    // Update clock
    updateClock();
    setInterval(updateClock, 1000);

    // Periodic metrics fetch
    setInterval(fetchMetrics, 5000);

    // Fetch scenarios via REST as a fallback
    fetch('/api/scenarios').then(r => r.json()).then(scenarios => {
      if (state.scenarios.length === 0) {
        state.scenarios = scenarios;
        renderScenarios(scenarios);
      }
    }).catch(() => { });

    console.log('%c SOC-MINI Dashboard Loaded ', 'background: #00f5a0; color: #0a0e17; font-weight: bold; padding: 4px 8px; border-radius: 4px;');
  }

  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
