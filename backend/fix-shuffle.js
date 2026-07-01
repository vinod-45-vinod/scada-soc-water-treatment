const https = require('https');
const API = 'fc602414-7eb8-493a-8ba4-2bd1cda9ce49';
const WF_ID = 'bbf856cc-2d63-4997-8837-efe3aa803fe8';
const VT_KEY = '77da7c48fa596b8e7850eb7bf2d67977344f1273a64c4e6b7184ab82c301a790';
const MISP_KEY = 'dWaBfWhjHgSwbAGkMImSfJAWqfuB9HqGvH5Kzgce';

function apiRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: 'shuffler.io', path, method,
      headers: { 'Authorization': 'Bearer ' + API, 'Content-Type': 'application/json' },
    };
    const req = https.request(opts, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(d) }); }
        catch { resolve({ status: res.statusCode, data: d }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

async function main() {
  // 1. Get workflow
  console.log('Fetching workflow...');
  const { data: wf } = await apiRequest('GET', '/api/v1/workflows/' + WF_ID);
  console.log('Workflow:', wf.name, '| Actions:', wf.actions?.length);

  // 2. Fix VirusTotal node
  const vtAction = wf.actions.find(a => a.label === 'VirusTotal');
  if (vtAction) {
    vtAction.parameters.forEach(p => {
      if (p.name === 'url') {
        p.value = 'https://www.virustotal.com/api/v3/ip_addresses/$exec.source_ip';
        console.log('  VT URL set:', p.value);
      }
      if (p.name === 'headers') {
        p.value = 'x-apikey: ' + VT_KEY;
        console.log('  VT headers set');
      }
    });
  }

  // 3. Fix MISP node
  const mispAction = wf.actions.find(a => a.label === 'MISP');
  if (mispAction) {
    mispAction.parameters.forEach(p => {
      if (p.name === 'url') {
        p.value = 'https://localhost:8443/attributes/restSearch';
        console.log('  MISP URL set:', p.value);
      }
      if (p.name === 'headers') {
        p.value = 'Authorization: ' + MISP_KEY + '\nContent-Type: application/json\nAccept: application/json';
        console.log('  MISP headers set');
      }
      if (p.name === 'body') {
        p.value = '{"returnFormat":"json","value":"$exec.source_ip"}';
        console.log('  MISP body set');
      }
    });
  }

  // 4. Fix Send_Alert node
  const sendAction = wf.actions.find(a => a.label === 'Send_Alert' || a.label === 'send_alert');
  if (sendAction) {
    sendAction.parameters.forEach(p => {
      if (p.name === 'url') {
        p.value = 'http://localhost:3000/api/shuffle/webhook';
        console.log('  Send_Alert URL set:', p.value);
      }
      if (p.name === 'headers') {
        p.value = 'Content-Type: application/json';
      }
      if (p.name === 'body') {
        p.value = '{"source":"$exec","vt":"$virustotal","misp":"$misp"}';
        console.log('  Send_Alert body set');
      }
    });
  }

  // 5. Ensure trigger is running
  if (wf.triggers) {
    wf.triggers.forEach(t => {
      if (t.trigger_type === 'WEBHOOK') {
        t.status = 'running';
        console.log('  Webhook trigger set to running');
      }
    });
  }

  // 6. Save workflow
  console.log('\nSaving workflow...');
  const { status } = await apiRequest('PUT', '/api/v1/workflows/' + WF_ID, wf);
  console.log('Save result: HTTP', status);

  // 7. Test webhook
  console.log('\nTesting webhook...');
  const testPayload = {
    source_ip: '45.33.32.156',
    event_type: 'LOGIN_ATTEMPT',
    description: 'Brute force login test from SOC-MINI',
    threat_severity: 'HIGH',
    mitre_id: 'T1110',
    mitre_technique: 'Brute Force',
    username: 'root',
    status: 'FAILED',
    incident_id: 'TEST-' + Date.now(),
    timestamp: new Date().toISOString(),
  };

  await new Promise(r => setTimeout(r, 3000)); // Wait for save to propagate

  const hookResult = await new Promise((resolve) => {
    const payload = JSON.stringify(testPayload);
    const req = https.request({
      hostname: 'shuffler.io',
      path: '/api/v1/hooks/webhook_95f8eb33-a08e-4b99-915a-ab52dd2b9fcd',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, body: d }));
    });
    req.write(payload); req.end();
  });

  console.log('Webhook test: HTTP', hookResult.status, hookResult.body.slice(0, 150));
  console.log('\nDone!');
}

main().catch(e => console.error('Error:', e.message));
