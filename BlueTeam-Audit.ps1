<#
.SYNOPSIS
    PowerShell Blue Team Audit Script
.DESCRIPTION
    Collects system, user, process, network, persistence, and additional blue team forensic information.
    Outputs a structured Markdown report.
.AUTHOR
    Aung Myat Thu [w01f]
#>

# Output Markdown file
$report = "$env:USERPROFILE\Desktop\SystemAudit-Report.md"
New-Item -Path $report -ItemType File -Force | Out-Null

function Write-Header($title) {
    Add-Content -Path $report -Value "`n## $title`n"
}

function Write-Sub($subtitle) {
    Add-Content -Path $report -Value "`n### $subtitle`n"
}

function Write-Content($content) {
    Add-Content -Path $report -Value "``````powershell`n$content`n``````"
}

# --- System Info ---
Write-Header "System Information"
$sysinfo = Get-ComputerInfo | Select-Object CsName, WindowsVersion, OsArchitecture, CsDomain, BiosSerialNumber
Write-Content ($sysinfo | Format-List | Out-String)

# --- Boot Time & Uptime ---
Write-Sub "Uptime & Boot Time"
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptime = New-TimeSpan -Start $boot
Write-Content "Boot Time: $boot`nUptime: $uptime"

# --- User Sessions ---
Write-Header "User Sessions"
$users = query user
Write-Content $users

# --- Local Users & Groups ---
Write-Header "Local Users & Groups"
Write-Sub "Local Users"
Write-Content (Get-LocalUser | Format-Table | Out-String)
Write-Sub "Administrators Group Members"
Write-Content (Get-LocalGroupMember -Group "Administrators" | Format-Table | Out-String)

# --- Running Processes ---
Write-Header "Running Processes (Top 15 by CPU)"
Write-Content (Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 | Format-Table | Out-String)

# --- Network Connections ---
Write-Header "Network Connections (Established)"
$connections = Get-NetTCPConnection -State Established | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        ProcessName = $proc.ProcessName
        PID         = $_.OwningProcess
        RemoteIP    = $_.RemoteAddress
        RemotePort  = $_.RemotePort
        State       = $_.State
    }
}
Write-Content ($connections | Sort-Object RemoteIP | Format-Table | Out-String)

# --- Startup Programs ---
Write-Header "Startup Programs"
Write-Content (Get-CimInstance Win32_StartupCommand | Format-Table Name, Command, Location, User -AutoSize | Out-String)

# --- Autorun Registry Keys ---
Write-Header "Registry Autoruns (HKLM Run)"
Write-Content (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Out-String)

# --- Security Events (Logon Events) ---
Write-Header "Security Event Logs"
$logons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 5
$failures = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5
Write-Sub "Successful Logons (Event ID 4624)"
Write-Content ($logons | Select-Object TimeCreated, Message | Out-String)
Write-Sub "Failed Logons (Event ID 4625)"
Write-Content ($failures | Select-Object TimeCreated, Message | Out-String)

# --- File System Changes ---
Write-Header "File System: Recently Modified Files (Last 24 Hours)"
$recent = Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Force | Where-Object {
    $_.LastWriteTime -gt (Get-Date).AddDays(-1) -and -not $_.PSIsContainer
} | Select-Object FullName, LastWriteTime -First 20
Write-Content ($recent | Format-Table -AutoSize | Out-String)

# --- Shadow Copies ---
Write-Header "Shadow Copies"
Write-Content (Get-WmiObject Win32_ShadowCopy | Out-String)

# --- Installed Hotfixes ---
Write-Header "Installed Hotfixes"
Write-Content (Get-HotFix | Format-Table -AutoSize | Out-String)

# --- LSASS Hash Example ---
Write-Header "File Hash: LSASS"
$file = "C:\Windows\System32\lsass.exe"
if (Test-Path $file) {
    $hash = Get-FileHash $file -Algorithm SHA256
    Write-Content ($hash | Format-List | Out-String)
} else {
    Write-Content "File not found: $file"
}

# --- Suspicious Services ---
Write-Header "Suspicious Services (cmd.exe or powershell in path)"
$suspServices = Get-WmiObject win32_service | Where-Object {
    $_.PathName -like "*cmd*" -or $_.PathName -like "*powershell*"
}
Write-Content ($suspServices | Format-Table Name, StartName, PathName, State -AutoSize | Out-String)

# --- Scheduled Tasks ---
Write-Header "Scheduled Tasks"
Write-Content (Get-ScheduledTask | Format-Table TaskName, TaskPath, State | Out-String)

# --- DNS Cache Dump ---
Write-Header "DNS Cache Dump"
Write-Content (ipconfig /displaydns)

# --- Firewall Rules ---
Write-Header "Firewall Rules"
Write-Content (Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Format-Table DisplayName, Direction, Action, Enabled -AutoSize | Out-String)

# --- Sysmon Log Sample (if available) ---
Write-Header "Sysmon Events (Event ID 1 - Process Create)"
if (Get-WinEvent -ListLog * | Where-Object {$_.LogDisplayName -like "*Sysmon*"} ) {
    $sysmon = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 5
    Write-Content ($sysmon | Select-Object TimeCreated, Message | Out-String)
} else {
    Write-Content "Sysmon not detected on this system."
}

# --- User Privileges ---
Write-Header "Users with Potential Privilege Escalation"
$adminUsers = Get-LocalGroupMember -Group "Administrators"
Write-Content ($adminUsers | Format-Table Name, ObjectClass, PrincipalSource | Out-String)

# --- Final Notice ---
Add-Content -Path $report -Value "`n---`n_Audit completed on $(Get-Date)_"

# --- Open Report ---
Start-Process notepad.exe $report
