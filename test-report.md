# PSTS Security Analysis Report

**Generated:** 2025-10-23 13:34:26
**Repository:** J-Ellette/PowerShellTestingSuite
**Branch:** refs/heads/copilot/implement-phase-1
**Commit:** test

---

## Summary

⚠️ **Total Violations:** 35

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 0 |
| 🔵 Low | 0 |

## Violations by Type
- **CertificateValidation:** 11 occurrence(s)
- **InsecureHashAlgorithms:** 5 occurrence(s)
- **CommandInjection:** 4 occurrence(s)
- **CredentialExposure:** 3 occurrence(s)

---

## Detailed Findings

### ⚪ 3 Severity (16)

#### InsecureHashAlgorithms

**File:** `all-violations.ps1` (Line 4)  
**Message:** Insecure hash algorithm 'MD5' detected. Use SHA-256 or higher.

```powershell
Get-FileHash -Path "file.txt" -Algorithm MD5
```

#### InsecureHashAlgorithms

**File:** `all-violations.ps1` (Line 18)  
**Message:** Insecure hash algorithm 'SHA1' detected. Use SHA-256 or higher.

```powershell
Get-FileHash -Path "data.bin" -Algorithm SHA1
```

#### CertificateValidation

**File:** `all-violations.ps1` (Line 1)  
**Message:** Certificate validation bypass detected

```powershell
# Test script with multiple types of violations

# Insecure hash algorithm
$hash = Get-FileHash -Path "file.txt" -Algorithm MD5

# Credential exposure
$pass = ConvertTo-SecureString "Password123" -AsPlainText -Force

# Command injection
$cmd = Read-Host "Command"
Invoke-Expression $cmd

# Certificate bypass
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# More violations
$apiKey = "hardcoded-api-key-secret"
$sha1Hash = Get-FileHash -Path "data.bin" -Algorithm SHA1

Write-Host "This script intentionally contains multiple security violations for testing purposes"

```

#### CertificateValidation

**File:** `all-violations.ps1` (Line 4)  
**Message:** Certificate validation bypass detected

```powershell
$hash = Get-FileHash -Path "file.txt" -Algorithm MD5

# Credential exposure
$pass = ConvertTo-SecureString "Password123" -AsPlainText -Force

# Command injection
$cmd = Read-Host "Command"
Invoke-Expression $cmd

# Certificate bypass
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# More violations
$apiKey = "hardcoded-api-key-secret"
$sha1Hash = Get-FileHash -Path "data.bin" -Algorithm SHA1

Write-Host "This script intentionally contains multiple security violations for testing purposes"
```

#### CertificateValidation

**File:** `all-violations.ps1` (Line 14)  
**Message:** Certificate validation bypass detected

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
```

#### CertificateValidation

**File:** `certificate-bypass.ps1` (Line 1)  
**Message:** Certificate validation bypass detected

```powershell
# Test script with certificate validation bypass violations

# Violation 1: Certificate callback that always returns true
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Violation 2: Disabling certificate revocation check
[System.Net.ServicePointManager]::CheckCertificateRevocationList = $false

# Violation 3: Certificate validation bypass in function
function Skip-CertificateValidation {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
}

# Correct usage (should not trigger violation)
# Proper certificate validation would implement actual checks
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $certificate, $chain, $sslPolicyErrors)
    
    # Implement proper validation logic here
    if ($sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None) {
        return $true
    }
    
    # Additional validation logic
    return $false
}

```

#### CertificateValidation

**File:** `certificate-bypass.ps1` (Line 4)  
**Message:** Certificate validation bypass detected

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Violation 2: Disabling certificate revocation check
[System.Net.ServicePointManager]::CheckCertificateRevocationList = $false

# Violation 3: Certificate validation bypass in function
function Skip-CertificateValidation {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
}

# Correct usage (should not trigger violation)
# Proper certificate validation would implement actual checks
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $certificate, $chain, $sslPolicyErrors)
    
    # Implement proper validation logic here
    if ($sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None) {
        return $true
    }
    
    # Additional validation logic
    return $false
}
```

#### CertificateValidation

**File:** `certificate-bypass.ps1` (Line 4)  
**Message:** Certificate validation bypass detected

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
```

#### CertificateValidation

**File:** `certificate-bypass.ps1` (Line 10)  
**Message:** Certificate validation bypass detected

```powershell
function Skip-CertificateValidation {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
}
```

#### CertificateValidation

**File:** `certificate-bypass.ps1` (Line 10)  
**Message:** Certificate validation bypass detected

```powershell
{
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
}
```

#### CertificateValidation

**File:** `certificate-bypass.ps1` (Line 11)  
**Message:** Certificate validation bypass detected

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
```

#### CertificateValidation

**File:** `certificate-bypass.ps1` (Line 11)  
**Message:** Certificate validation bypass detected

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
```

#### CertificateValidation

**File:** `certificate-bypass.ps1` (Line 16)  
**Message:** Certificate validation bypass detected

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $certificate, $chain, $sslPolicyErrors)
    
    # Implement proper validation logic here
    if ($sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None) {
        return $true
    }
    
    # Additional validation logic
    return $false
}
```

#### InsecureHashAlgorithms

**File:** `insecure-hash.ps1` (Line 4)  
**Message:** Insecure hash algorithm 'MD5' detected. Use SHA-256 or higher.

```powershell
Get-FileHash -Path "C:\temp\file.txt" -Algorithm MD5
```

#### InsecureHashAlgorithms

**File:** `insecure-hash.ps1` (Line 7)  
**Message:** Insecure hash algorithm 'SHA1' detected. Use SHA-256 or higher.

```powershell
Get-FileHash -Path "C:\temp\another.txt" -Algorithm SHA1
```

#### InsecureHashAlgorithms

**File:** `insecure-hash.ps1` (Line 10)  
**Message:** Direct usage of insecure hash algorithm class detected

```powershell
[System.Security.Cryptography.MD5]
```

### ⚪ 4 Severity (7)

#### CredentialExposure

**File:** `all-violations.ps1` (Line 7)  
**Message:** Plaintext password conversion detected. Use Read-Host -AsSecureString instead.

```powershell
ConvertTo-SecureString "Password123" -AsPlainText -Force
```

#### CommandInjection

**File:** `all-violations.ps1` (Line 11)  
**Message:** Potential command injection via Invoke-Expression with variables

```powershell
Invoke-Expression $cmd
```

#### CommandInjection

**File:** `command-injection.ps1` (Line 5)  
**Message:** Potential command injection via Invoke-Expression with variables

```powershell
Invoke-Expression $userInput
```

#### CommandInjection

**File:** `command-injection.ps1` (Line 9)  
**Message:** Potential command injection via Invoke-Expression with variables

```powershell
iex $command
```

#### CommandInjection

**File:** `command-injection.ps1` (Line 13)  
**Message:** Potential command injection via Invoke-Expression with variables

```powershell
Invoke-Expression $scriptBlock
```

#### CredentialExposure

**File:** `credential-exposure.ps1` (Line 4)  
**Message:** Plaintext password conversion detected. Use Read-Host -AsSecureString instead.

```powershell
ConvertTo-SecureString "MyPassword123!" -AsPlainText -Force
```

#### CredentialExposure

**File:** `credential-exposure.ps1` (Line 8)  
**Message:** Plaintext password conversion detected. Use Read-Host -AsSecureString instead.

```powershell
ConvertTo-SecureString "DatabasePassword!" -AsPlainText -Force
```

---

## Recommendations

### Best Practices

- Use SHA-256 or higher for cryptographic hashing
- Never store credentials in plaintext
- Avoid Invoke-Expression with user input
- Always validate SSL/TLS certificates
- Use PowerShell approved verbs and cmdlets
- Implement proper error handling
- Follow the principle of least privilege

### Resources

- [PowerShell Security Best Practices](https://docs.microsoft.com/powershell/scripting/security/)
- [PSTS Documentation](https://github.com/J-Ellette/PowerShellTestingSuite)

---

*Generated by PSTS v1.0.0*
