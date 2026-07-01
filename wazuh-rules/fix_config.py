import re

conf_path = '/var/ossec/etc/ossec.conf'

with open(conf_path, 'r') as f:
    content = f.read()

# Remove all existing remote blocks
content = re.sub(r'\s*<remote>.*?</remote>', '', content, flags=re.DOTALL)

new_remote = """
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>0.0.0.0/0</allowed-ips>
  </remote>
"""

content = content.replace('<ossec_config>', '<ossec_config>' + new_remote, 1)

with open(conf_path, 'w') as f:
    f.write(content)

print('ossec.conf updated: syslog listener added on UDP 514')
