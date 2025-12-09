<#
WINDOWS BASIC HARDENING SCRIPT
Level  : BASIC
Author : Security Automation
Run As : Administrator
Rollback Supported
#>

# =========================
# GLOBAL PATHS
# =========================
$Root           = "C:\Hardening"
$Log            = Join-Path $Root "basic.log"
$SystemBackup   = Join-Path $Root "basic_system_backup.reg"
$PoliciesBackup = Join-Path $Root "basic_policies_backup.reg"

New-Item -ItemType Directory -Path $Root -Force | Out-Null

# =========================
# LOG FUNCTION
# =========================
function Write-Log {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    $line | Out-File -Append -FilePath $Log -Encoding utf8
    Write-Host $line
}

# =========================
# ADMIN CHECK
# =========================
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Run this script as Administrator"
    exit 1
}

Write-Log "BASIC HARDENING STARTED"

# =========================
# REGISTRY BACKUP FOR ROLLBACK
# =========================
try {
    reg export "HKLM\SYSTEM" $SystemBackup /y | Out-Null
    reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" $PoliciesBackup /y | Out-Null
    Write-Log "Registry backups created"
} catch {
    Write-Log "Registry backup failed: $_"
}

# =========================
# BASIC PASSWORD POLICY
# =========================
try {
    net accounts /minpwlen:8  | Out-Null
    net accounts /maxpwage:60 | Out-Null
    net accounts /lockoutthreshold:3 | Out-Null
    net accounts /lockoutduration:10 | Out-Null

    Write-Log "Basic password & lockout policy applied"
} catch {
    Write-Log " Password policy failed: $_"
}

# =========================
# BASIC SECURITY OPTIONS
# =========================
try {
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f | Out-Null
    Write-Log "Blank passwords blocked"
} catch {
    Write-Log "Blank password policy failed: $_"
}

# =========================
# INTERACTIVE LOGON BANNER
# =========================
$sys = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

try {
    reg add $sys /v LegalNoticeText    /t REG_SZ /d "Authorized access only." /f | Out-Null
    reg add $sys /v LegalNoticeCaption /t REG_SZ /d "Warning" /f | Out-Null

    Write-Log "Login banner enabled"
} catch {
    Write-Log "Login banner failed: $_"
}

# =========================
# WINDOWS DEFENDER ENABLE
# =========================
try {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Write-Log " Windows Defender enabled"
} catch {
    Write-Log "Defender enable failed: $_"
}

# =========================
# FIREWALL BASIC ENABLE
# =========================
try {
    netsh advfirewall set allprofiles state on | Out-Null
    Write-Log "Firewall enabled on all profiles"
} catch {
    Write-Log "Firewall enable failed: $_"
}

# =========================
# AUTOPLAY DISABLE
# =========================
try {
    $expl = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    reg add $expl /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f | Out-Null

    Write-Log "AutoRun disabled"
} catch {
    Write-Log "Autorun setting failed: $_"
}

# =========================
# FINAL STATUS
# =========================
Write-Log "BASIC HARDENING COMPLETED"
Write-Host ""
Write-Host "BASIC HARDENING SUCCESSFUL"
Write-Host "Log file: $Log"
Write-Host "Rollback backups:"
Write-Host $SystemBackup
Write-Host $PoliciesBackup
Write-Host ""
Write-Host "System restart is recommended"
