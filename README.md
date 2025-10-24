# PSTS - PowerShell Testing Suite

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/J-Ellette/PowerShellTestingSuite/powershell-security.yml?branch=main)
![License](https://img.shields.io/github/license/J-Ellette/PowerShellTestingSuite)
![Version](https://img.shields.io/badge/version-1.0.0-blue)

**PSTS (PowerShell Testing Suite)** is a comprehensive security analysis tool for PowerShell scripts that integrates with GitHub Actions, provides AI-powered auto-fixes, and offers multiple deployment options.

## 🎯 Features

### Phase 1: GitHub Workflow Integration ✅
- **Automated Security Analysis**: Runs on every push and pull request
- **16 Security Rules**: Comprehensive PowerShell security coverage
  - **Core Rules (4)**: Insecure hashing, credential exposure, command injection, certificate validation
  - **PowerShell-Specific Rules (12)**: Execution policy bypass, unsafe remoting, version downgrades, privilege escalation, and more
- **SARIF Output**: Integrates with GitHub Security tab
- **AI-Powered Auto-Fix**: Automatically generates and applies security fixes
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
    
    - name: Run PSTS Analysis
      shell: pwsh
      run: |
        Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force
        $result = Invoke-WorkspaceAnalysis -WorkspacePath "."
        
        # Export results
        $result | ConvertTo-Json -Depth 10 | Out-File 'psts-results.json'
        
        # Generate SARIF
        . ./scripts/Convert-ToSARIF.ps1
        Convert-ToSARIF -InputFile 'psts-results.json' -OutputFile 'psts-results.sarif'
    
    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: psts-results.sarif
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
```

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

For detailed examples of all rules, see the [test scripts](tests/TestScripts/).

## 🤖 AI Auto-Fix

PSTS includes an AI-powered auto-fix action that can automatically remediate security violations:

```yaml
- name: Apply AI Fixes
  uses: ./actions/copilot-autofix
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    violations-file: 'psts-results.json'
    apply-fixes: true
    confidence-threshold: 0.8
```

**Features**:
- Generates fixes based on security best practices
- Confidence scoring for each fix
- Applies fixes only when confidence threshold is met
- Creates detailed commit messages

## 📊 SARIF Integration

PSTS generates SARIF (Static Analysis Results Interchange Format) output that integrates with GitHub's Security tab:

1. Results appear in the **Security** → **Code scanning** tab
2. Violations are annotated directly in pull requests
3. Track security trends over time
4. Filter by severity, rule, and file

## ⚙️ Configuration

PSTS includes configurable options for customizing analysis behavior.

### Excluded Paths

By default, PSTS excludes test scripts from workspace analysis to avoid flagging intentional violations used for testing:

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
│   └── TestScripts/        # Scripts with known violations
└── buildplans/             # Technical documentation
```

### Running Tests

```powershell
# Test the analyzer on sample vulnerable scripts
pwsh -Command "
    Import-Module ./src/PowerShellSecurityAnalyzer.psm1
    Get-ChildItem ./tests/TestScripts/*.ps1 | ForEach-Object {
        Write-Host \"Testing: $($_.Name)\"
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

PSTS is designed with security in mind:
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