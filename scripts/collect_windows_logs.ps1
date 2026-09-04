# =============================================
# HOME SOC - WINDOWS LOG COLLECTOR
# =============================================

$LOG_DIR = "C:\homesoc\logs"

$UBUNTU_USER = "socadmin"
$UBUNTU_IP = "192.168.8.129"
$UBUNTU_LOG_DIR = "/home/socadmin/homesoc/logs"

# =============================================
# PREPARATION
# =============================================

Write-Host "================================="
Write-Host "       WINDOWS SOC COLLECTOR"
Write-Host "================================="
Write-Host ""

Write-Host "[+] Collecting Windows Security logs..."

New-Item -ItemType Directory -Force -Path $LOG_DIR | Out-Null

# =============================================
# CREATE TIMESTAMP
# =============================================

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

$logFile = "$LOG_DIR\windows_security_$timestamp.log"

# =============================================
# COLLECT SECURITY EVENTS
# =============================================

$events = Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4624,4625,4672
} -MaxEvents 500

# =============================================
# WRITE EVENTS
# =============================================

"===== WINDOWS SECURITY EVENTS =====" |
    Out-File -FilePath $logFile -Encoding UTF8

"Collected: $(Get-Date)" |
    Out-File -FilePath $logFile -Append -Encoding UTF8

"" |
    Out-File -FilePath $logFile -Append -Encoding UTF8

foreach ($event in $events) {

    "----------------------------------------" |
        Out-File -FilePath $logFile -Append -Encoding UTF8

    "TimeCreated : $($event.TimeCreated)" |
        Out-File -FilePath $logFile -Append -Encoding UTF8

    "EventID     : $($event.Id)" |
        Out-File -FilePath $logFile -Append -Encoding UTF8

    "Message     :" |
        Out-File -FilePath $logFile -Append -Encoding UTF8

    $event.Message |
        Out-File -FilePath $logFile -Append -Encoding UTF8

    "" |
        Out-File -FilePath $logFile -Append -Encoding UTF8
}

# =============================================
# COLLECTION COMPLETE
# =============================================

Write-Host "[+] Collection complete."
Write-Host "[+] Log saved to: $logFile"

# =============================================
# TRANSFER TO UBUNTU SOC
# =============================================

Write-Host ""
Write-Host "[+] Transferring log to Ubuntu SOC..."

scp $logFile "${UBUNTU_USER}@${UBUNTU_IP}:${UBUNTU_LOG_DIR}/"

if ($LASTEXITCODE -eq 0) {

    Write-Host "[+] Transfer successful."

}
else {

    Write-Host "[!] Transfer failed."

}

Write-Host ""
Write-Host "[+] Windows collection complete."