# quartermaster-watchdog.ps1
# Bounded 5-minute visible watchdog (5 cycles of 60s sleep).
# Checks Herdr / background status and pings quartermaster with CHECK TIME.
# Appends concise status to tools/quartermaster-watchdog.log.

$LogFile = "F:\coding\shallow-copy\tools\quartermaster-watchdog.log"
$PidFile = "F:\coding\shallow-copy\tools\quartermaster-watchdog.pid"
$StopFile = "F:\coding\shallow-copy\tools\quartermaster-watchdog.stop"

Set-Content -Path $PidFile -Value $PID -Force

$cycle = 0
while (-not (Test-Path -LiteralPath $StopFile)) {
    for ($minute = 1; $minute -le 5; $minute++) {
        if (Test-Path -LiteralPath $StopFile) { break }
        Start-Sleep -Seconds 60
    }
    if (Test-Path -LiteralPath $StopFile) { break }
    $cycle++
    $TimeStamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    $LogEntry = "[$TimeStamp] [Cycle $cycle] CHECK TIME: Quartermaster check prompt."
    Add-Content -Path $LogFile -Value $LogEntry
    herdr agent prompt quartermaster "CHECK TIME: inspect active milestones, stalled owners, and usage thresholds now." 2>&1 |
        Out-File -FilePath $LogFile -Append -Encoding utf8
}
