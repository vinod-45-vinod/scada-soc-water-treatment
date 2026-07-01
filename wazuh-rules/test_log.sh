#!/bin/bash
echo 'SCADA_SOC: event_type=LOGIN_ATTEMPT "Failed login attempt" source_ip=198.51.100.23 status=FAILED ioa_type=BRUTE_FORCE_BEHAVIOR mitre_id=T1110 threat_severity=CRITICAL threat_intel_tag=THREAT_INTEL_MATCH' | /var/ossec/bin/wazuh-logtest
