# Initial Details
Project: Home SOC

Virtualization:
- VMware Workstation

Networks:
- VMnet8 — NAT — 192.168.67.0/24
- VMnet1 — Host-only — 192.168.8.0/24

Kali:
- Role: Analyst / Attacker
- eth0: 192.168.67.128
- eth1: 192.168.8.128

Ubuntu:
- Role: Monitored Linux Endpoint
- ens33: 192.168.67.129
- ens34: 192.168.8.129
- Hostname: homesoc-ubuntu
- SSH: Enabled

Verified:
- Kali → Internet: Working
- Kali → Ubuntu: Working
- Kali → Ubuntu SSH: Working