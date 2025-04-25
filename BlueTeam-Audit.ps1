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

# Markdown formatting helpers
function Write-Header($title) {
    Add-Content -Path $report -Value "`n## $title`n"
}

function Write-Sub($subtitle) {
    Add-Content -Path $report -Value "`n### $subtitle`n"
}

function Write-Content($content) {
    Add-Content -Path $report -Value "```powershell`n$content`n```"
}

# --- Markdown TOC ---
Add-Content -Path $report -Value "# System Audit Report"
Add-Content -Path $report -Value "_Generated: $(Get-Date)_`n"
Add-Content -Path $report -Value "## Table of Contents"
$sections = @(
    "System Information",
    "User Sessions",
    "Local Users & Groups",
    "Running Processes (Top 15 by CPU)",
    "Network Connections (Established)",
    "Startup Programs",
    "Registry Autoruns (HKLM Run)",
    "Security Event Logs",
    "File System: Recently Modified Files (Last 24 Hours)",
    "Shadow Copies",
    "Installed Hotfixes",
    "File Hash: LSASS",
    "Suspicious Services (cmd.exe or powershell in path)",
    "Scheduled Tasks",
    "DNS Cache Dump",
    "Firewall Rules",
    "Sysmon Events (Event ID 1 - Process Create)",
    "Users with Potential Privilege Escalation"
)

$i = 1
foreach ($section in $sections) {
    $anchor = $section -replace '[^a-zA-Z0-9 ]', '' -replace ' ', '-'
    Add-Content -Path $report -Value "$i. [$section](#$anchor)"
    $i++
}

function Get-WindowsStartupPrograms {
    $results = @()
    $suspiciousPaths = @("appdata", "temp", "recycle", "programdata\\.*\\temp")
    $suspiciousExtensions = @(".js", ".vbs", ".bat", ".ps1", ".hta")
    $suspiciousPatterns = @("powershell", "cmd.exe", "-enc", "frombase64string")

    function Is-Suspicious($path) {
        $lower = $path.ToLower()
        foreach ($pat in $suspiciousPaths) {
            if ($lower -match $pat) { return $true }
        }
        foreach ($ext in $suspiciousExtensions) {
            if ($lower -like "*$ext") { return $true }
        }
        foreach ($str in $suspiciousPatterns) {
            if ($lower -like "*$str*") { return $true }
        }
        return $false
    }

    $userStartupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $userStartupPath) {
        Get-ChildItem -Path $userStartupPath -Force | ForEach-Object {
            $results += [PSCustomObject]@{
                Source     = "Startup Folder (Current User)"
                Name       = $_.Name
                Path       = $_.FullName
                Suspicious = Is-Suspicious($_.FullName)
            }
        }
    }

    $allUsersStartupPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $allUsersStartupPath) {
        Get-ChildItem -Path $allUsersStartupPath -Force | ForEach-Object {
            $results += [PSCustomObject]@{
                Source     = "Startup Folder (All Users)"
                Name       = $_.Name
                Path       = $_.FullName
                Suspicious = Is-Suspicious($_.FullName)
            }
        }
    }

    $regCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    if (Test-Path $regCU) {
        Get-ItemProperty -Path $regCU | ForEach-Object {
            $_.PSObject.Properties | ForEach-Object {
                $results += [PSCustomObject]@{
                    Source     = "Registry (HKCU)"
                    Name       = $_.Name
                    Path       = $_.Value
                    Suspicious = Is-Suspicious($_.Value)
                }
            }
        }
    }

    $regLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    if (Test-Path $regLM) {
        Get-ItemProperty -Path $regLM | ForEach-Object {
            $_.PSObject.Properties | ForEach-Object {
                $results += [PSCustomObject]@{
                    Source     = "Registry (HKLM)"
                    Name       = $_.Name
                    Path       = $_.Value
                    Suspicious = Is-Suspicious($_.Value)
                }
            }
        }
    }

    return $results
}

# --- System Info ---
Write-Header "System Information"
$sysinfo = Get-ComputerInfo | Select-Object CsName, WindowsVersion, OsArchitecture, CsDomain, BiosSerialNumber
Write-Sub "Uptime & Boot Time"
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptime = New-TimeSpan -Start $boot
Write-Content "Boot Time: $boot`nUptime: $uptime"
Write-Content ($sysinfo | Format-List | Out-String)

# --- User Sessions ---
Write-Header "User Sessions"
Write-Content (query user)

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

# --- Windows Startup Programs (Registry + Folders) with Suspicion Flag ---
Write-Header "Windows Startup Programs (Registry + Folders)"
$startupItems = Get-WindowsStartupPrograms
Write-Content ($startupItems | Sort-Object Suspicious -Descending | Format-Table -AutoSize | Out-String)

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

# --- LSASS File Hash ---
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

# --- DNS Cache ---
Write-Header "DNS Cache Dump"
Write-Content (ipconfig /displaydns)

# --- Firewall Rules ---
Write-Header "Firewall Rules"
Write-Content (Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Format-Table DisplayName, Direction, Action, Enabled -AutoSize | Out-String)

# --- Sysmon Logs (if available) ---
Write-Header "Sysmon Events (Event ID 1 - Process Create)"
if (Get-WinEvent -ListLog * | Where-Object {$_.LogDisplayName -like "*Sysmon*"} ) {
    $sysmon = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 5
    Write-Content ($sysmon | Select-Object TimeCreated, Message | Out-String)
} else {
    Write-Content "Sysmon not detected on this system."
}

# --- Privilege Escalation Risks ---
Write-Header "Users with Potential Privilege Escalation"
$adminUsers = Get-LocalGroupMember -Group "Administrators"
Write-Content ($adminUsers | Format-Table Name, ObjectClass, PrincipalSource | Out-String)

# --- Final Line ---
Add-Content -Path $report -Value "`n---`n_Report generated by Aung Myat Thu [w01f] on $(Get-Date)_"

# --- Open Markdown Report in Notepad ---
Start-Process notepad.exe $report
