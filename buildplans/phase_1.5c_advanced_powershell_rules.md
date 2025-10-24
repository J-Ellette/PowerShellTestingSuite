# PSTS Phase 1.5C - Advanced PowerShell Security Rules

> Generated on October 24, 2025

## Overview

This document outlines **Phase 1.5C** - Advanced PowerShell-specific security rules that address modern attack vectors, version-specific vulnerabilities, and enterprise security concerns. These rules build upon the successful Phase 1.5B implementation to create the most comprehensive PowerShell security platform available.

## 🎯 **Phase 1.5C Goals**

- **Modern Threat Detection**: AMSI/ETW evasion, JEA bypasses
- **Version Security**: Enhanced PowerShell 2.0 and cross-version issues  
- **Enterprise/Cloud**: Azure PowerShell, Active Directory, Certificate security
- **Supply Chain**: PowerShell Gallery and module security

## 🚨 **Immediate Implementation (Phase 1.5C-A)**

### **Rule 31: AMSI Evasion Detection**
**Priority**: 🔥 CRITICAL - Used in 90% of modern PowerShell attacks

```powershell
# Detection patterns:
- [System.Management.Automation.AmsiUtils]::amsiInitFailed
- $amsiContext manipulation
- AmsiScanBuffer/AmsiScanString bypasses
- Reflection-based AMSI disabling
- Memory patching attempts

# Test script needed: amsi-evasion.ps1
```

**Business Impact**: Detects the most common PowerShell attack technique used by advanced persistent threats.

### **Rule 32: ETW Evasion Detection**  
**Priority**: 🔥 CRITICAL - Prevents security monitoring

```powershell
# Detection patterns:
- Set-EtwTraceProvider manipulation
- ETW provider disabling
- Event log clearing attempts
- LoggingSettings modification
- ScriptBlockLogging bypass

# Test script needed: etw-evasion.ps1
```

**Business Impact**: Identifies attempts to disable security logging and monitoring.

### **Rule 33: Enhanced PowerShell 2.0 Detection**
**Priority**: 🔥 CRITICAL - Expands current detection

```powershell
# Enhanced detection beyond current rule:
- Specific PowerShell 2.0 ISE usage
- .NET 2.0 Framework dependencies
- WMI-based PowerShell 2.0 execution
- COM object PowerShell 2.0 invocation
- Registry-based version forcing

# Test script needed: enhanced-ps2-detection.ps1
```

**Business Impact**: Comprehensive protection against PowerShell 2.0 downgrade attacks.

## ⚡ **High Priority Implementation (Phase 1.5C-B)**

### **Rule 34: Azure PowerShell Credential Leaks**
**Priority**: ⚡ HIGH - Cloud security critical

```powershell
# Detection patterns:
- Connect-AzAccount with plaintext passwords
- Service Principal secrets in variables
- $AzContext credential exposure
- Azure Key Vault unsafe access
- Storage account key hardcoding

# Test script needed: azure-credential-leaks.ps1
```

### **Rule 35: PowerShell Gallery Security**
**Priority**: ⚡ HIGH - Supply chain protection

```powershell
# Detection patterns:
- Install-Module without -Scope CurrentUser
- Find-Module with unsafe sources
- Unsigned module installation
- Import-Module from untrusted paths
- Known malicious module patterns

# Test script needed: gallery-security.ps1
```

### **Rule 36: Certificate Store Manipulation**
**Priority**: ⚡ HIGH - PKI security

```powershell
# Detection patterns:
- Get-ChildItem Cert:\ with export attempts
- Certificate private key extraction
- Self-signed certificate installation
- Root certificate store modification
- Certificate validation bypasses

# Test script needed: certificate-manipulation.ps1
```

### **Rule 37: Active Directory Dangerous Operations**
**Priority**: ⚡ HIGH - Enterprise identity protection

```powershell
# Detection patterns:
- Get-ADUser with unsafe LDAP filters
- Set-ADUser bulk operations without confirmation
- Add-ADGroupMember with privileged groups
- Unsafe AD replication operations
- AD credential handling

# Test script needed: ad-dangerous-operations.ps1
```

## 📋 **Medium Priority Implementation (Phase 1.5C-C)**

### **Rule 38: JEA Configuration Vulnerabilities**
**Priority**: 📋 MEDIUM - Enterprise administration security

```powershell
# Detection patterns:
- Unsafe RoleCapabilities definitions
- SessionConfiguration security gaps
- EndpointConfiguration bypasses
- JEA session manipulation
- Privilege escalation through JEA

# Test script needed: jea-vulnerabilities.ps1
```

### **Rule 39: DSC Security Issues**
**Priority**: 📋 MEDIUM - Infrastructure as Code security

```powershell
# Detection patterns:
- Unsafe Configuration data handling
- MOF file credential exposure
- DSC credential storage issues
- Configuration drift detection
- DSC resource security gaps

# Test script needed: dsc-security.ps1
```

### **Rule 40: Deprecated Cmdlet Usage**
**Priority**: 📋 MEDIUM - Legacy security improvements

```powershell
# Detection patterns:
- ConvertTo-SecureString -AsPlainText without -Force
- New-Object System.Net.WebClient
- [System.Web.Security.Membership] usage
- Legacy cryptography cmdlets
- Deprecated authentication methods

# Test script needed: deprecated-cmdlets.ps1
```

## 🔬 **Experimental/Future Rules (Phase 1.5C-D)**

### **Rule 41: Cross-Platform Security Issues**
```powershell
# PowerShell 7+ cross-platform considerations
- Linux/macOS specific vulnerabilities
- Case-sensitive filesystem issues
- Unix permission problems
- Path traversal differences
```

### **Rule 42: PowerShell Remoting Advanced Attacks**
```powershell
# Advanced remoting security beyond current rules
- PSSession hijacking attempts
- Invoke-Command security bypasses
- Remoting configuration attacks
- WinRM security gaps
```

### **Rule 43: Memory Analysis Evasion**
```powershell
# Advanced memory-based attacks
- Process hollowing detection
- Memory injection patterns
- Reflective DLL loading
- Fileless malware indicators
```

## 📊 **Implementation Strategy**

### **Phase 1.5C-A: Immediate (1-2 weeks)**
1. **AMSI Evasion Detection** - Most critical modern threat
2. **ETW Evasion Detection** - Monitoring protection
3. **Enhanced PowerShell 2.0 Detection** - Expand existing rule

**Expected Impact**: Detects 90%+ of modern PowerShell attacks

### **Phase 1.5C-B: High Priority (2-3 weeks)**
4. **Azure PowerShell Credential Leaks** - Cloud security
5. **PowerShell Gallery Security** - Supply chain protection
6. **Certificate Store Manipulation** - PKI security
7. **Active Directory Dangerous Operations** - Enterprise identity

**Expected Impact**: Enterprise-grade cloud and identity protection

### **Phase 1.5C-C: Medium Priority (3-4 weeks)**
8. **JEA Configuration Vulnerabilities** - Administrative security
9. **DSC Security Issues** - Infrastructure security
10. **Deprecated Cmdlet Usage** - Legacy modernization

**Expected Impact**: Comprehensive administrative and infrastructure protection

## 🎯 **Success Metrics**

### **Technical Metrics**
- **Rule Coverage**: 40+ total security rules
- **Attack Detection**: 95%+ of known PowerShell attack techniques
- **Version Support**: PowerShell 2.0 through 7.x coverage
- **Platform Support**: Windows, Linux, macOS considerations

### **Enterprise Metrics**
- **Cloud Security**: Azure/AWS/GCP PowerShell protection
- **Identity Security**: Active Directory and certificate protection
- **Compliance**: SOC 2, NIST, CIS framework alignment
- **Supply Chain**: Module and gallery security validation

## 🚀 **Market Position After Phase 1.5C**

With Phase 1.5C complete, PSTS will have:

- **40+ Security Rules** (most comprehensive PowerShell security platform)
- **Modern Threat Detection** (AMSI/ETW evasion, latest attack techniques)
- **Enterprise Cloud Security** (Azure, AD, certificate protection)
- **Version Compatibility** (PowerShell 2.0 through 7.x coverage)
- **Supply Chain Security** (Gallery and module protection)

**Result**: PSTS becomes the **definitive enterprise PowerShell security platform** with unmatched coverage and depth.

## 💡 **Implementation Notes**

### **Test Script Organization**
```
tests/TestScripts/
├── powershell/           # Existing 17 scripts
│   ├── amsi-evasion.ps1             # New
│   ├── etw-evasion.ps1              # New  
│   ├── enhanced-ps2-detection.ps1   # New
│   ├── azure-credential-leaks.ps1   # New
│   ├── gallery-security.ps1         # New
│   ├── certificate-manipulation.ps1 # New
│   ├── ad-dangerous-operations.ps1  # New
│   ├── jea-vulnerabilities.ps1      # New
│   ├── dsc-security.ps1             # New
│   └── deprecated-cmdlets.ps1       # New
```

### **Rule ID Convention**
- Rules 31-33: Immediate Priority (Phase 1.5C-A)
- Rules 34-37: High Priority (Phase 1.5C-B)  
- Rules 38-40: Medium Priority (Phase 1.5C-C)
- Rules 41-43: Future/Experimental (Phase 1.5C-D)

---

*This document represents the roadmap for making PSTS the most comprehensive PowerShell security platform in the industry.*