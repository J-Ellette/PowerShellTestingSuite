# PSTS Phase 1 Master Plan
## The Definitive PowerShell Security Platform Roadmap

> **Last Updated**: October 24, 2025
> **Status**: Phase 1.5C-A Complete | Next: Phase 1.5C-B  
> **Vision**: Build the #1 PowerShell security testing suite on the market

---

## 📊 Current State

### ✅ Phase 1 Complete (v1.0.0)
- **4 core security rules** (InsecureHashAlgorithms, CredentialExposure, CommandInjection, CertificateValidation)
- **GitHub Actions workflow** with SARIF upload and PR comments
- **Basic auto-fix action** (rule-based, mock AI integration)
- **Test suite** with 28+ test scripts across 5 categories
- **Supporting scripts** (SARIF converter, report generator)

### ✅ Phase 1.5A-B Complete (v1.5.0)
- **16 PowerShell-specific rules** (ExecutionPolicyBypass, ScriptBlockLogging, PSRemoting, etc.)
- **14 general security rules** (Network: HTTP/TLS, FileSystem: Permissions/PathTraversal, Registry: Credentials, Data: SQL/LDAP injection)
- **30 total security rules implemented**

### ✅ Phase 1.5C-A Complete (v1.5.1)
- **3 advanced PowerShell rules** (AMSIEvasion, ETWEvasion, EnhancedPowerShell2Detection)
- **33 total security rules** - detecting modern attack vectors
- **Market leadership** in PowerShell security rule coverage

---

## 🎯 Strategic Vision

### Market Position Goal
**Be THE definitive PowerShell security platform** that:
1. **Detects 95%+ of real-world PowerShell attacks**
2. **Provides AI-powered intelligent auto-fixes**
3. **Integrates seamlessly into enterprise workflows**
4. **Scales from individual developers to enterprise teams**
5. **Sets the industry standard for PowerShell security**

### Core Differentiators
- ✅ **Most comprehensive rule coverage** (33+ rules, targeting 40+)
- ⚡ **Modern threat detection** (AMSI/ETW evasion, supply chain attacks)
- 🤖 **Real AI-powered fixes** (not mock implementations)
- 🏢 **Enterprise-ready** (governance, compliance, scalability)
- 🚀 **Developer-first** (VS Code, pre-commit hooks, real-time analysis)

---

## 🔥 CRITICAL PRIORITY (Implement Immediately)

### 1. Real AI Auto-Fix Implementation 🤖
**Current**: Mock implementation with template-based fixes  
**Target**: Production-ready AI integration  
**Impact**: CRITICAL - Core value proposition  

#### Solution: Multi-Provider AI Integration

**Primary: GitHub Models API** (Free tier with GPT-4o-mini)
```typescript
// Use existing GITHUB_TOKEN
endpoint: "https://models.inference.ai.azure.com/chat/completions"
model: "gpt-4o-mini"
```

**Secondary Providers**: OpenAI, Azure OpenAI, Anthropic Claude

**Configuration** (.psts.yml):
```yaml
autofix:
  provider: "github-models"  # github-models, openai, azure, claude
  model: "gpt-4o-mini"
  max_fixes: 10
  confidence_threshold: 0.8
  fallback_to_templates: true
```

**Features**:
- Context-aware fixes (understand broader script purpose)
- Multi-line complex fixes
- Fix validation (re-run analysis to verify)
- Alternative fix suggestions
- Learning from accepted/rejected fixes

**Deliverables**:
- [ ] Replace mock Copilot API calls with real GitHub Models integration
- [ ] Add multi-provider configuration system
- [ ] Implement template-based fallback
- [ ] Add fix validation and re-analysis
- [ ] Create comprehensive fix tests
- [ ] Update documentation with AI setup

---

### 2. Configuration System (.psts.yml) ⚙️
**Current**: Hardcoded configuration  
**Target**: Flexible, hierarchical configuration  
**Impact**: HIGH - Enables enterprise adoption  

#### Comprehensive Configuration File

**Location**: `.psts.yml` (repository root, with global/org level support)

**Structure**:
```yaml
# PSTS Configuration
version: "1.0"

# Analysis Settings
analysis:
  severity_threshold: "Medium"  # Low, Medium, High, Critical
  max_file_size: 10485760  # 10MB
  timeout_seconds: 30
  parallel_analysis: true
  
  # Path exclusions
  exclude_paths:
    - "**/node_modules/**"
    - "**/dist/**"
    - "**/*.min.ps1"
  
  # File exclusions
  exclude_files:
    - "*.tests.ps1"

# Rule Configuration
rules:
  # Enable/disable rules
  InsecureHashAlgorithms:
    enabled: true
    severity: "High"  # Override default severity
  
  CredentialExposure:
    enabled: true
    severity: "Critical"
    # Rule-specific config
    check_comments: true
    min_password_length: 8
  
  # Disable specific rules
  DeprecatedCmdletUsage:
    enabled: false

# Auto-Fix Configuration
autofix:
  enabled: true
  provider: "github-models"
  model: "gpt-4o-mini"
  max_fixes: 10
  confidence_threshold: 0.8
  apply_automatically: false
  
  # Per-rule auto-fix control
  rule_fixes:
    InsecureHashAlgorithms: true
    CommandInjection: false  # Too risky for auto-fix

# Suppression Settings
suppressions:
  require_justification: true
  max_duration_days: 90
  allow_permanent: false

# Reporting
reporting:
  formats: ["sarif", "json", "markdown"]
  output_dir: ".psts-reports"
  
  # SARIF settings
  sarif:
    include_code_flows: true
    include_fixes: true
  
  # Report customization
  markdown:
    include_severity_summary: true
    include_top_issues: 5

# CI/CD Integration
ci:
  fail_on: ["Critical", "High"]
  max_warnings: 50
  baseline_mode: false
  baseline_file: ".psts-baseline.sarif"

# Webhooks (for Slack, Teams, etc.)
webhooks:
  - url: "https://hooks.slack.com/..."
    events: ["critical_found", "analysis_complete"]
    severity_filter: ["Critical", "High"]

# Enterprise Settings
enterprise:
  audit_log: true
  compliance_reporting: true
  policy_enforcement: true
```

**Deliverables**:
- [ ] Create configuration schema and validator
- [ ] Implement hierarchical config loading (global → org → project → local)
- [ ] Wire configuration to analyzer engine
- [ ] Add config validation CLI command
- [ ] Document configuration options
- [ ] Provide example templates for common scenarios

---

### 3. Suppression Comment System 🔕
**Current**: No suppression mechanism  
**Target**: Flexible, auditable suppression system  
**Impact**: HIGH - Reduces false positive friction  

#### Suppression Formats

```powershell
# Single line suppression
# PSTS-SUPPRESS-NEXT: InsecureHashAlgorithms - Legacy system requirement
$hash = Get-FileHash -Algorithm MD5 $file

# Inline suppression
$password = "temp123" # PSTS-SUPPRESS: CredentialExposure - Test credential

# Block suppression
# PSTS-SUPPRESS-START: CommandInjection - Validated input only
$commands | ForEach-Object { Invoke-Expression $_ }
# PSTS-SUPPRESS-END

# Expiring suppression
# PSTS-SUPPRESS-NEXT: InsecureHashAlgorithms - Until migration complete (2025-12-31)
[System.Security.Cryptography.MD5]::Create()
```

**Features**:
- Require justification (configurable)
- Expiry dates with automatic alerts
- Suppression tracking and reporting
- Audit trail of all suppressions
- Team review workflow for suppressions

**Deliverables**:
- [ ] Implement suppression comment parser
- [ ] Add expiry date checking and warnings
- [ ] Create suppression report generator
- [ ] Add suppression audit log
- [ ] Document suppression best practices

---

### 4. Phase 1.5C-B: High-Priority Advanced Rules ⚡
**Current**: 33 rules implemented  
**Target**: 37 rules (add 4 critical advanced rules)  
**Impact**: HIGH - Enterprise cloud security  

#### Azure & Cloud Security Rules

**Rule 34: AzurePowerShellCredentialLeaks** (CRITICAL)
```powershell
# Detect:
- Connect-AzAccount with plaintext passwords
- Service Principal secrets in variables
- $AzContext credential exposure
- Azure Key Vault unsafe access
- Storage account key hardcoding
```

**Rule 35: PowerShellGallerySecurity** (HIGH)
```powershell
# Detect:
- Install-Module without -Scope CurrentUser
- Find-Module with untrusted sources
- Unsigned module installation
- Import-Module from untrusted paths
- Known malicious module patterns
```

**Rule 36: CertificateStoreManipulation** (HIGH)
```powershell
# Detect:
- Certificate private key extraction
- Self-signed certificate installation
- Root certificate store modification
- Certificate export to insecure locations
```

**Rule 37: ActiveDirectoryDangerousOperations** (HIGH)
```powershell
# Detect:
- Unsafe LDAP filters in Get-ADUser
- Bulk AD operations without confirmation
- Add-ADGroupMember with privileged groups
- Unsafe AD replication operations
- AD credential handling issues
```

**Deliverables**:
- [ ] Implement 4 high-priority rules with test scripts
- [ ] Add comprehensive test coverage
- [ ] Update documentation and examples
- [ ] Generate fix templates for each rule

---

## ⚡ HIGH PRIORITY (Phase 1.5C-C)

### 5. Enhanced Rule Coverage - Phase 1.5C-C 📋
**Target**: 40+ total security rules  
**Impact**: HIGH - Comprehensive coverage  

#### Medium-Priority Rules

**Rule 38: JEAConfigurationVulnerabilities**
- Unsafe RoleCapabilities definitions
- SessionConfiguration security gaps
- JEA privilege escalation vectors

**Rule 39: DSCSecurityIssues**
- Unsafe Configuration data handling
- MOF file credential exposure
- DSC credential storage issues

**Rule 40: DeprecatedCmdletUsage**
- ConvertTo-SecureString -AsPlainText without -Force warning
- Legacy New-Object System.Net.WebClient usage
- Deprecated authentication methods

---

### 6. Advanced PowerShell Attack Detection 🛡️
**Target**: Detect advanced real-world attack patterns  
**Impact**: HIGH - Modern threat protection  

#### Advanced Attack Patterns (from newPSsuggestions.md)

**PowerShell Obfuscation Detection**
- Base64 encoded commands
- String concatenation obfuscation
- Character code conversion
- Format string obfuscation
- Reversed strings

**Download Cradle Detection**
- `IEX (New-Object Net.WebClient).DownloadString(...)`
- Memory-only execution patterns
- BitsTransfer + execution chains

**Persistence Mechanism Detection**
- Registry Run keys
- Scheduled task creation
- WMI event subscriptions
- PowerShell profile modifications

**Credential Harvesting Detection**
- Mimikatz patterns
- LSASS dumping
- Browser credential extraction
- WiFi password dumping

**Lateral Movement Detection**
- WMI/CIM remote execution
- Remote scheduled tasks
- SMB share enumeration
- Pass-the-Hash techniques

**Data Exfiltration Detection**
- DNS tunneling
- HTTP POST with large data
- Pastebin/GitHub Gist uploads
- Cloud storage uploads

**Deliverables**:
- [ ] Implement 6 advanced attack pattern detection rules
- [ ] Create realistic test scripts based on real malware
- [ ] Map to MITRE ATT&CK framework
- [ ] Add remediation guidance for each pattern

---

### 7. Pre-Commit Hook Integration 🪝
**Current**: CI/CD only  
**Target**: Local validation before commit  
**Impact**: HIGH - Shift-left security  

#### Git Hook Features

**Installation**:
```bash
# Automatic setup
psts install-hooks

# Manual setup
cp .psts/hooks/pre-commit .git/hooks/
```

**Capabilities**:
- Run analysis on staged files only
- Block commits with critical violations
- Auto-fix on commit (opt-in)
- Fast incremental analysis
- Configurable severity blocking

**Deliverables**:
- [ ] Create pre-commit hook script
- [ ] Add hook installation command to CLI
- [ ] Implement staged-file-only analysis
- [ ] Add configuration options
- [ ] Document hook setup and usage

---

### 8. Performance Optimization & Metrics 🚀
**Current**: Single-threaded, no metrics  
**Target**: Enterprise-scale performance  
**Impact**: HIGH - Large codebase support  

#### Optimization Features

**Parallel Processing**:
- Multi-file parallel analysis
- Rule parallelization per file
- Configurable worker threads

**Incremental Analysis**:
- Only analyze changed files in CI/CD
- Git-aware change detection
- Smart caching of results

**Performance Metrics**:
```yaml
metrics:
  total_analysis_time: "12.3s"
  files_per_second: 45
  rules_per_second: 1350
  cache_hit_rate: 0.82
  memory_peak_mb: 256
```

**Deliverables**:
- [ ] Implement parallel file analysis
- [ ] Add incremental analysis mode
- [ ] Create performance metrics tracking
- [ ] Add performance regression tests
- [ ] Optimize AST parsing and caching

---

### 9. Enhanced SARIF Output 📊
**Current**: Basic SARIF 2.1.0  
**Target**: Full SARIF features with rich metadata  
**Impact**: MEDIUM-HIGH - Better GitHub integration  

#### SARIF Enhancements

**Rich Metadata**:
- CWE/CVE mappings for all rules
- MITRE ATT&CK technique IDs
- OWASP category mappings
- Remediation help URLs

**Code Flows**:
- Data flow visualization for complex vulnerabilities
- Call chains for security issues

**Fix Suggestions**:
- Include fix suggestions in SARIF
- Multiple fix alternatives
- Fix explanation and impact

**Deliverables**:
- [ ] Add CWE mappings to all rules
- [ ] Implement code flow tracking
- [ ] Add fix suggestions to SARIF
- [ ] Enhance SARIF metadata
- [ ] Validate against SARIF schema 2.1.0

---

### 10. CLI Wrapper & Developer Experience 🛠️
**Current**: Module-only interface  
**Target**: Comprehensive CLI with developer tools  
**Impact**: MEDIUM-HIGH - Improved usability  

#### CLI Commands

```powershell
# Analysis
psts analyze [path]
psts analyze --format sarif
psts analyze --baseline

# Configuration
psts config validate
psts config init
psts config show

# Baseline Management
psts baseline create
psts baseline compare

# Fix Management
psts fix preview
psts fix apply --confidence 0.8

# Installation
psts install-hooks
psts version
```

**Deliverables**:
- [ ] Create psts.ps1 CLI wrapper
- [ ] Implement all commands with help
- [ ] Add output formatting options
- [ ] Create interactive mode
- [ ] Document CLI usage

---

## 📋 MEDIUM PRIORITY (Phase 1.6 - 2-3 Months)

### 11. CI/CD Platform Integrations 🔄
**Current**: GitHub Actions only  
**Target**: Multi-platform support  

**Platforms**:
- Azure DevOps Pipelines
- GitLab CI/CD
- Jenkins
- CircleCI
- TeamCity

**Deliverables per platform**:
- Native integration (plugin/extension/orb)
- SARIF upload to platform security features
- PR/MR comment integration
- Configuration documentation

---

### 12. Rule Marketplace & Community Plugins 🎪
**Target**: Extensible rule ecosystem  
**Impact**: HIGH - Community growth  

**Features**:
- YAML-based custom rule definitions
- Rule templates and generator
- Community rule repository
- Rule quality certification
- Usage analytics

**Rule Definition Format**:
```yaml
rule:
  id: "CustomRule001"
  name: "My Custom Security Check"
  severity: "High"
  category: "Security"
  cwe: "CWE-XXX"
  
  patterns:
    - type: "command"
      command: "Invoke-CustomUnsafeCmd"
      message: "Unsafe command detected"
    
    - type: "regex"
      pattern: "dangerous-pattern"
      message: "Dangerous pattern found"
  
  remediation: |
    Use the safe alternative: Invoke-SafeCmd
```

---

### 13. Baseline & Diff Mode 📸
**Target**: Track new violations only  
**Impact**: MEDIUM-HIGH - Incremental improvement  

**Features**:
- Create baseline from current state
- Compare against baseline
- Report only NEW violations
- Baseline versioning and management
- Team baseline sharing

---

### 14. Compliance Reporting 📜
**Target**: Enterprise governance & compliance  
**Impact**: MEDIUM - Enterprise adoption  

**Compliance Frameworks**:
- NIST Cybersecurity Framework
- CIS PowerShell Security Benchmark
- OWASP Top 10
- SOC 2 requirements
- PCI-DSS
- HIPAA security rules

**Reports**:
- Compliance dashboard
- Gap analysis reports
- Audit evidence collection
- Policy enforcement tracking

---

### 15. Webhook Integrations 🔗
**Target**: Real-time notifications  
**Impact**: MEDIUM - Team collaboration  

**Integration Targets**:
- Slack (rich cards with severity indicators)
- Microsoft Teams (adaptive cards)
- Jira (automatic issue creation)
- ServiceNow (incident creation)
- Email notifications

---

### 16. Historical Trending & Analytics 📈
**Target**: Security posture over time  
**Impact**: MEDIUM - Strategic insights  

**Features**:
- Violation trends over time
- Security score evolution
- Team comparison metrics
- Rule effectiveness tracking
- Fix success rate analysis

---

## 🎯 STRATEGIC PRIORITIES (Phase 2 Prep - 3-4 Months)

### 17. VS Code Extension Foundation 💻
**Aligns with**: Phase 2 planning  
**Impact**: HIGH - Developer adoption  

**Phase 2 Prep Features**:
- Export diagnostics JSON for Language Server
- Real-time analysis API
- Quick fix suggestion format
- VS Code command schema

---

### 18. Multi-Format Output 📄
**Target**: Support diverse tooling ecosystems  

**Formats**:
- JSON (current)
- SARIF (current)
- Markdown (current)
- XML (SonarQube compatibility)
- CSV (spreadsheet import)
- HTML (standalone reports)
- JUnit XML (test reporting)

---

### 19. Advanced Secret Detection 🔐
**Target**: Comprehensive credential detection  
**Impact**: HIGH - Prevent credential leaks  

**Detection Capabilities**:
- AWS Access Keys (regex + entropy)
- Azure Storage Keys
- GitHub tokens
- API keys (various formats)
- Private keys (PEM, SSH, etc.)
- Database connection strings
- OAuth tokens
- Cryptocurrency wallet keys

---

### 20. Performance Benchmarking & Testing 🔬
**Target**: Enterprise-grade performance validation  

**Benchmark Suite**:
- Analysis speed (files/second)
- Scalability tests (100s of files)
- Memory usage profiling
- Rule execution timing
- Comparison against competitors

---

## 🚀 FUTURE VISION (Phase 2+)

### Phase 2: VS Code Extension
- Real-time analysis as you type
- Inline security suggestions
- Quick fix code actions
- Security-aware IntelliSense
- Team rule sharing

### Phase 3: Standalone Application
- Electron desktop app
- Docker sandbox isolation
- Local AI integration (Ollama)
- Enterprise security policies
- Offline operation support

---

## 🎓 Community & Ecosystem

### Community Building
- Open source rule contributions
- Security researcher partnerships
- Bug bounty program
- Community forums and Discord
- Regular security webinars

### Documentation
- Comprehensive rule documentation
- Security best practices guide
- Video tutorials
- Interactive examples
- Translation to multiple languages

---

## 📊 Success Metrics

### Adoption Metrics
- **GitHub Stars**: >1000 (current baseline)
- **Weekly Active Users**: >500
- **Enterprise Adoptions**: >10
- **Community Contributors**: >50

### Quality Metrics
- **False Positive Rate**: <5%
- **Auto-Fix Success Rate**: >90%
- **User Satisfaction**: >4.5/5
- **Rule Coverage**: 95%+ of known PowerShell attacks

### Performance Metrics
- **Analysis Speed**: >50 files/second
- **CI Overhead**: <30 seconds
- **Memory Usage**: <500MB
- **Cost per Scan**: <$0.01

---

## 🔄 Implementation Workflow

### For Each Feature
1. **Design**: Detailed technical design document
2. **Test-First**: Create test scripts and expected outputs
3. **Implementation**: Core functionality with error handling
4. **Integration**: Wire into existing system
5. **Documentation**: Update all relevant docs
6. **Validation**: End-to-end testing and review

### Release Cadence
- **Minor Releases**: Every 2-3 weeks (new rules, improvements)
- **Major Releases**: Every 2-3 months (new capabilities)
- **Patch Releases**: As needed (bug fixes, security updates)

---

## 🎯 Next Steps (Immediate Actions)

### Critical Foundation
1. **Real AI Integration**: GitHub Models API implementation
2. **Configuration System**: Basic .psts.yml support
3. **Suppression Comments**: Parser and basic functionality

### Advanced Rules
4. **Phase 1.5C-B Rules**: Azure, Gallery, Certificate, AD rules
5. **Test Coverage**: Comprehensive test scripts
6. **Documentation**: Updated with new features

### Developer Experience
7. **Pre-commit Hooks**: Local validation
8. **CLI Wrapper**: Basic commands
9. **Performance**: Incremental analysis

### Enterprise Features
10. **Enhanced SARIF**: CWE mappings, code flows
11. **Compliance**: Basic compliance reporting
12. **Baseline Mode**: Track new violations only

---

## 📚 Related Documents

- **TechnicalPlan.md**: Overall architecture and technical strategy
- **Phase_1_GitHub_Workflow_Implementation.md**: Phase 1 implementation details
- **Phase_2_VS_Code_Extension_Implementation.md**: VS Code extension plans
- **Phase_3_Standalone_Sandbox_Application.md**: Standalone app vision
- **IMPLEMENTATION_SUMMARY.md**: Current implementation status

---

## 💡 Guiding Principles

1. **PowerShell-First**: Deep PowerShell expertise over generic security
2. **Developer Experience**: Make security easy and frictionless
3. **Enterprise-Ready**: Scale from individual to organization
4. **AI-Powered**: Intelligent automation, not just rule matching
5. **Open & Extensible**: Community-driven ecosystem
6. **Quality Over Quantity**: Lower false positives beat more rules
7. **Continuous Improvement**: Iterate based on real-world feedback

---

**Status**: Living document - updated with each phase completion  
**Owner**: PSTS Core Team  
**Last Review**: October 24, 2025

---

*This master plan consolidates insights from multiple planning documents and prioritizes features that will establish PSTS as the #1 PowerShell security testing suite on the market.*
