#!/bin/bash
# Configure Wazuh Manager to forward alerts to Shuffle SOAR webhook
# This script adds the integration to ossec.conf inside the Docker container

SHUFFLE_WEBHOOK="https://shuffler.io/api/v1/hooks/webhook_0e727e93-41c8-4edb-baac-97aad31dc463"

# Create the integration config
cat > /tmp/shuffle_integration.xml << 'EOF'
  <!-- Shuffle SOAR Integration - Forward high-severity SCADA alerts -->
  <integration>
    <name>shuffle</name>
    <hook_url>https://shuffler.io/api/v1/hooks/webhook_0e727e93-41c8-4edb-baac-97aad31dc463</hook_url>
    <level>10</level>
    <rule_id>100112,100121,100123,100140,100141,100142,100143,100180,100181,100182,100183,100184,100186,100190,100191</rule_id>
    <alert_format>json</alert_format>
  </integration>
EOF

echo "Shuffle integration config created."
echo "Add the contents of /tmp/shuffle_integration.xml to /var/ossec/etc/ossec.conf"
echo "inside the <ossec_config> block."
