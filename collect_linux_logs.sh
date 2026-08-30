#!/bin/bash

LOG_DIR="$HOME/homesoc/logs"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

mkdir -p "$LOG_DIR"

echo "[+] Collecting Linux authentication logs..."

sudo cp /var/log/auth.log "$LOG_DIR/auth_$TIMESTAMP.log"

echo "[+] Collecting system journal..."

sudo journalctl --no-pager > "$LOG_DIR/journal_$TIMESTAMP.log"

echo "[+] Collection complete."
echo "[+] Logs saved to: $LOG_DIR"