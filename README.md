## PowerShell Cheat Sheet – **Blue Team Edition** by w01f

---

### **System Information**

```powershell
# Basic system info
Get-ComputerInfo

# Environment variables
Get-ChildItem Env:

# System boot time
(Get-CimInstance -ClassName win32_operatingsystem).LastBootUpTime

# Uptime
(New-TimeSpan -Start (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToString()

# Installed hotfixes
Get-HotFix

# Running services
Get-Service | Where-Object {$_.Status -eq "Running"}
```

---

### **User & Group Recon**

```powershell
# List all users
Get-LocalUser

# List all groups
Get-LocalGroup

# List members of a group
Get-LocalGroupMember -Group "Administrators"

# Currently logged in user
whoami

# Logged-in sessions
quser
query user
```

---

### **Process and Task Analysis**

```powershell
# List running processes
Get-Process

# List processes with network connections
Get-NetTCPConnection -State Established | 
  ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        ProcessName = $proc.ProcessName
        PID         = $_.OwningProcess
        RemoteIP    = $_.RemoteAddress
        RemotePort  = $_.RemotePort
        State       = $_.State
    }
} | Sort-Object RemoteIP

# List startup processes
Get-CimInstance Win32_StartupCommand | 
Select-Object Name, command, Location, User

# Suspicious parent-child process relationships
Get-WmiObject Win32_Process | ForEach-Object {
    $_ | Select-Object ProcessId, ParentProcessId, Name
}
```

---

### **Security & Event Logs**

```powershell
# List event logs
Get-EventLog -List

# Read Security log (last 50 events)
Get-EventLog -LogName Security -Newest 50

# Filter logon events (Event ID 4624)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} | 
  Select-Object TimeCreated, Message -First 10

# Failed logon attempts (Event ID 4625)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
  Select-Object TimeCreated, Message -First 10
```

---

### **Network Info & Monitoring**

```powershell
# Get IP configuration
Get-NetIPAddress

# Get ARP cache
Get-NetNeighbor

# Open network ports and listening services
Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'}

# Active network connections
netstat -anob
```

---

### **File & Disk Analysis**

```powershell
# List files in directory (recursive)
Get-ChildItem -Recurse

# Get file hash (e.g. for integrity checking)
Get-FileHash -Algorithm SHA256 "C:\path\to\file.exe"

# Search for recently modified files (last 1 day)
Get-ChildItem -Recurse | 
Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) }

# List shadow copies (if any)
Get-WmiObject Win32_ShadowCopy
```

---

### **Persistence Checks**

```powershell
# Scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}

# Autoruns (Registry)
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

# Services with suspicious paths
Get-WmiObject win32_service | 
  Where-Object { $_.PathName -like "*cmd*" -or $_.PathName -like "*powershell*" }
```

---

### **Incident Response Essentials**

```powershell
# Dump current running processes to CSV
Get-Process | Export-Csv -Path "$env:USERPROFILE\Desktop\running_processes.csv" -NoTypeInformation

# Export event log for review
wevtutil epl Security "$env:USERPROFILE\Desktop\SecurityLog.evtx"

# Collect netstat output
netstat -ano > "$env:USERPROFILE\Desktop\netstat.txt"
```

---

###  **Memory & Forensics Tools Integration (via PowerShell)**

```powershell
# Dump LSASS memory for offline analysis (admin required)
rundll32.exe comsvcs.dll, MiniDump (Get-Process lsass).Id lsass.dmp full

# Volatility-compatible memory dump using sysinternals
.\PsExec.exe -accepteula -s -i -d cmd.exe
```

> Always run memory collection with caution. Use tools like `DumpIt`, `Belkasoft RAM Capturer`, or `Magnet RAM Capture` where appropriate.

---

## Tools to Know

| Tool            | Use Case                           |
|-----------------|------------------------------------|
| Sysinternals    | Deep system monitoring             |
| PowerView       | AD recon and enumeration           |
| PowerForensics  | Disk forensics                     |
| SharpHound      | AD mapping (with caution)          |
| KAPE            | Forensic triage & evidence capture |
