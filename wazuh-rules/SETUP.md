# SOC-MINI: Wazuh Docker Setup Guide
# Municipal Water Treatment Plant SCADA/ICS SOC System

## Prerequisites
- Docker Desktop installed and running on Windows
- Wazuh Agent installed on the Windows host

---

## Step 1: Ensure Wazuh Docker Container Exposes UDP Port 514

If using docker-compose, add this to the Wazuh Manager service:

```yaml
services:
  wazuh.manager:
    # ... existing config ...
    ports:
      - "1514:1514"       # Agent communication
      - "1515:1515"       # Agent enrollment  
      - "514:514/udp"     # Syslog UDP (SCADA logs)
      - "55000:55000"     # Wazuh API
```

If the container is already running without port 514, you need to recreate it:

```bash
docker-compose down
docker-compose up -d
```

---

## Step 2: Configure Wazuh Manager to Listen on Syslog UDP 514

Enter the Wazuh Manager container:
```bash
docker exec -it wazuh.manager bash
```

Edit the Wazuh Manager config:
```bash
vi /var/ossec/etc/ossec.conf
```

Add the following inside `<ossec_config>`:
```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>0.0.0.0/0</allowed-ips>
</remote>
```

---

## Step 3: Install Custom SCADA Rules

From the Windows host, copy the rules file into the container:
```bash
docker cp wazuh-rules/scada_rules.xml wazuh.manager:/var/ossec/etc/rules/local_rules.xml
```

**IMPORTANT**: If you already have custom rules in local_rules.xml, append the SCADA rules instead of replacing.

---

## Step 4: Restart Wazuh Manager

```bash
docker exec wazuh.manager /var/ossec/bin/wazuh-control restart
```

---

## Step 5: Verify Syslog is Listening

```bash
docker exec wazuh.manager ss -lunp | grep 514
```

Expected output:
```
udp   UNCONN  0  0  *:514  *:*  users:(("wazuh-remoted",pid=XXX,fd=XX))
```

---

## Step 6: Configure Wazuh Agent (Optional File Monitoring)

On the Windows host, edit the Wazuh Agent config:
```
C:\Program Files (x86)\ossec-agent\ossec.conf
```

Add inside `<ossec_config>`:
```xml
<localfile>
  <log_format>json</log_format>
  <location>C:\Users\Vinod G R\Desktop\soc-mini\logs\scada-events.log</location>
</localfile>
```

Restart the Wazuh Agent:
```bash
net stop WazuhSvc
net start WazuhSvc
```

---

## Step 7: Verify Rule Loading

Check that rules loaded correctly:
```bash
docker exec wazuh.manager /var/ossec/bin/wazuh-logtest
```

Test with a sample log message:
```
SCADA_SOC: event_type=LOGIN_ATTEMPT "Failed login attempt" source_ip=198.51.100.23 status=FAILED ioc_type=MALICIOUS_IP ioa_type=BRUTE_FORCE_BEHAVIOR attack_stage=Initial Access mitre_id=T1110 threat_severity=CRITICAL threat_intel_tag=THREAT_INTEL_MATCH risk_score=100
```

Expected: Multiple rule matches (base rule → login rule → IoA rule → MITRE rule → CTI rule)

---

## Step 8: Start the SOC Application

```bash
cd soc-mini
npm install
npm start
```

Then open: http://localhost:3000

---

## Troubleshooting

### Logs not appearing in Wazuh Dashboard?
1. Check UDP port: `docker exec wazuh.manager ss -lunp | grep 514`
2. Check Wazuh logs: `docker exec wazuh.manager tail -f /var/ossec/logs/ossec.log`
3. Verify the SCADA app is sending to the correct IP/port
4. Update Wazuh target in the SOC dashboard Settings tab

### Finding your Docker container IP:
```bash
docker inspect wazuh.manager | findstr "IPAddress"
```

Use this IP in the SOC dashboard Settings if 127.0.0.1 doesn't work.

### Rules not triggering?
1. Verify rules loaded: `docker exec wazuh.manager /var/ossec/bin/wazuh-logtest`
2. Check for XML syntax errors in rules file
3. Ensure rule IDs don't conflict with existing rules
