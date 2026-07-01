# ============================================
# WAZUH AGENT SCADA SETUP - Run as Administrator
# ============================================

$agentDir = "C:\Program Files (x86)\ossec-agent"
$agentConf = "$agentDir\ossec.conf"
$agentLog = "$agentDir\ossec.log"
$scadaLog = "C:\Users\Vinod G R\Desktop\soc-mini\logs\scada-events.log"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WAZUH AGENT - SCADA LOG SETUP" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check agent service
Write-Host "[1] Checking Wazuh Agent service..." -ForegroundColor Yellow
$svc = Get-Service WazuhSvc -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "    Status: $($svc.Status)" -ForegroundColor $(if($svc.Status -eq 'Running'){'Green'}else{'Red'})
} else {
    Write-Host "    ERROR: WazuhSvc not found!" -ForegroundColor Red
    pause
    exit 1
}

# Step 2: Show current agent manager config
Write-Host ""
Write-Host "[2] Current manager connection:" -ForegroundColor Yellow
$content = Get-Content $agentConf -Raw
$match = [regex]::Match($content, '<server>[\s\S]*?</server>')
if ($match.Success) {
    Write-Host $match.Value -ForegroundColor Gray
}

# Step 3: Check if SCADA log is already configured
Write-Host ""
Write-Host "[3] Checking SCADA log monitoring..." -ForegroundColor Yellow
if ($content -match "scada-events\.log") {
    Write-Host "    Already configured!" -ForegroundColor Green
} else {
    Write-Host "    Adding SCADA log file monitoring..." -ForegroundColor Yellow
    
    $localfileBlock = @"

  <!-- SCADA SOC Log Monitoring -->
  <localfile>
    <log_format>json</log_format>
    <location>$scadaLog</location>
  </localfile>
"@
    $content = $content -replace "</ossec_config>", "$localfileBlock`n</ossec_config>"
    Set-Content -Path $agentConf -Value $content -Encoding UTF8 -NoNewline
    Write-Host "    DONE: Added SCADA log monitoring" -ForegroundColor Green
}

# Step 4: Show last agent errors
Write-Host ""
Write-Host "[4] Recent agent log entries:" -ForegroundColor Yellow
if (Test-Path $agentLog) {
    $logLines = Get-Content $agentLog -Tail 20
    foreach ($line in $logLines) {
        if ($line -match "error|warn|manager|connected|disconnected") {
            $color = if ($line -match "error") { "Red" } elseif ($line -match "warn") { "Yellow" } else { "Gray" }
            Write-Host "    $line" -ForegroundColor $color
        }
    }
} else {
    Write-Host "    No log file found" -ForegroundColor Red
}

# Step 5: Restart the agent
Write-Host ""
Write-Host "[5] Restarting Wazuh Agent..." -ForegroundColor Yellow
Stop-Service WazuhSvc -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Service WazuhSvc
Start-Sleep -Seconds 5

$svc = Get-Service WazuhSvc
Write-Host "    Agent Status: $($svc.Status)" -ForegroundColor $(if($svc.Status -eq 'Running'){'Green'}else{'Red'})

# Step 6: Show post-restart logs
Write-Host ""
Write-Host "[6] Post-restart log:" -ForegroundColor Yellow
Start-Sleep -Seconds 3
if (Test-Path $agentLog) {
    $logLines = Get-Content $agentLog -Tail 10
    foreach ($line in $logLines) {
        Write-Host "    $line" -ForegroundColor Gray
    }
}

# Step 7: Verify SCADA log file exists
Write-Host ""
Write-Host "[7] SCADA log file check:" -ForegroundColor Yellow
if (Test-Path $scadaLog) {
    $size = (Get-Item $scadaLog).Length
    $lines = (Get-Content $scadaLog | Measure-Object).Count
    Write-Host "    File exists: $scadaLog" -ForegroundColor Green
    Write-Host "    Size: $size bytes | Lines: $lines" -ForegroundColor Green
} else {
    Write-Host "    WARNING: $scadaLog not found!" -ForegroundColor Red
    Write-Host "    Start the SCADA simulation first to generate logs" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SETUP COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
