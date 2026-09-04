#!/bin/bash

echo "================================"
echo "        HOME SOC RUN"
echo "================================"

echo
echo "[+] Starting log collection..."
/home/socadmin/homesoc/scripts/collect_linux_logs.sh

echo
echo "[+] Starting log analysis..."
python3 /home/socadmin/homesoc/scripts/analyze_linux_logs.py

echo
echo "[+] Starting Windows log analysis..."
python3 /home/socadmin/homesoc/scripts/analyze_windows_logs.py

echo
echo "[+] Starting event correlation..."
python3 /home/socadmin/homesoc/scripts/correlate_events.py

echo
echo "[+] Generating alert summary..."
python3 /home/socadmin/homesoc/scripts/alert_summary.py

echo
echo "[+] Generating incidents..."
python3 /home/socadmin/homesoc/scripts/generate_incidents.py

echo
echo "[+] Running automated response..."
python3 /home/socadmin/homesoc/scripts/automated_response.py

echo
echo "[+] Generating dashboard..."
python3 /home/socadmin/homesoc/scripts/generate_dashboard.py

echo
echo "================================"
echo "[+] HOME SOC RUN COMPLETE"
echo "================================"