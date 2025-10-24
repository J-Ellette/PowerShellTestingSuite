#Requires -Version 7.0

<#
.SYNOPSIS
    PowerShell Security Analyzer Module for PSTS
.DESCRIPTION
    Analyzes PowerShell scripts for security vulnerabilities and provides detailed reports.
.NOTES
    Version: 1.0.0
    Author: PSTS Project
#>

using namespace System.Management.Automation.Language
using namespace System.Collections.Generic

# Enumerations
enum SecuritySeverity {
    Low = 1
    Medium = 2
    High = 3
    Critical = 4
}

# Classes
class SecurityViolation {
    [string]$Name
    [string]$Message
    [string]$Description
    [SecuritySeverity]$Severity
    [int]$LineNumber
    [string]$Code
    [string]$FilePath
    [string]$RuleId
    [hashtable]$Metadata

    SecurityViolation([string]$name, [string]$message, [SecuritySeverity]$severity, [int]$lineNumber, [string]$code) {
        $this.Name = $name
        $this.Message = $message
        $this.Severity = $severity
        $this.LineNumber = $lineNumber
        $this.Code = $code
        $this.Metadata = @{}
    }
}

class SecurityRule {
    [string]$Name
    [string]$Description
    [SecuritySeverity]$Severity
    [ScriptBlock]$Evaluator
    [string]$Category
    [string[]]$Tags

    SecurityRule([string]$name, [string]$description, [SecuritySeverity]$severity, [ScriptBlock]$evaluator) {
        $this.Name = $name
        $this.Description = $description
        $this.Severity = $severity
        $this.Evaluator = $evaluator
        $this.Category = "Security"
        $this.Tags = @()
    }

    [SecurityViolation[]] Evaluate([Ast]$ast, [string]$filePath) {
        $violations = & $this.Evaluator $ast $filePath
        foreach ($violation in $violations) {
            $violation.FilePath = $filePath
            $violation.RuleId = $this.Name
        }
        return $violations
    }
}

class PowerShellSecurityAnalyzer {
    [List[SecurityRule]]$SecurityRules
    [List[SecurityRule]]$CodingRules
    [hashtable]$Configuration

    PowerShellSecurityAnalyzer() {
        $this.SecurityRules = [List[SecurityRule]]::new()
        $this.CodingRules = [List[SecurityRule]]::new()
        $this.Configuration = @{
            EnableParallelAnalysis = $true
            MaxFileSize = 10MB
            TimeoutSeconds = 30
            ExcludedPaths = @('tests/TestScripts', '*/TestScripts', 'test/*', 'tests/*')
        }
        $this.InitializeDefaultRules()
    }

    [void] InitializeDefaultRules() {
        # Rule 1: Insecure Hash Algorithms
        $this.SecurityRules.Add([SecurityRule]::new(
            "InsecureHashAlgorithms",
            "Detects usage of cryptographically weak hash algorithms",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                $insecureAlgorithms = @('MD5', 'SHA1', 'SHA-1', 'RIPEMD160')
                
                # Check Get-FileHash calls
                $hashCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and $args[0].GetCommandName() -eq 'Get-FileHash'
                }, $true)
                
                foreach ($call in $hashCalls) {
                    $algorithmParam = $null
                    for ($i = 0; $i -lt $call.CommandElements.Count; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and $element.ParameterName -eq 'Algorithm') {
                            if ($i + 1 -lt $call.CommandElements.Count) {
                                $nextElement = $call.CommandElements[$i + 1]
                                if ($nextElement -is [StringConstantExpressionAst]) {
                                    $algorithmParam = $nextElement
                                }
                            }
                        }
                    }
                    
                    if ($algorithmParam -and $algorithmParam.Value -in $insecureAlgorithms) {
                        $violations += [SecurityViolation]::new(
                            "InsecureHashAlgorithms",
                            "Insecure hash algorithm '$($algorithmParam.Value)' detected. Use SHA-256 or higher.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Check .NET crypto classes
                $cryptoUsage = $Ast.FindAll({
                    $args[0] -is [TypeExpressionAst] -and
                    $args[0].TypeName.Name -match 'MD5|SHA1CryptoServiceProvider'
                }, $true)
                
                foreach ($usage in $cryptoUsage) {
                    $violations += [SecurityViolation]::new(
                        "InsecureHashAlgorithms",
                        "Direct usage of insecure hash algorithm class detected",
                        [SecuritySeverity]::High,
                        $usage.Extent.StartLineNumber,
                        $usage.Extent.Text
                    )
                }
                
                return $violations
            }
        ))

        # Rule 2: Credential Exposure
        $this.SecurityRules.Add([SecurityRule]::new(
            "CredentialExposure",
            "Detects potential credential exposure in scripts",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find ConvertTo-SecureString with -AsPlainText
                $secureStringCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'ConvertTo-SecureString'
                }, $true)
                
                foreach ($call in $secureStringCalls) {
                    $hasAsPlainText = $false
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [CommandParameterAst] -and $element.ParameterName -eq 'AsPlainText') {
                            $hasAsPlainText = $true
                            break
                        }
                    }
                    
                    if ($hasAsPlainText) {
                        $violations += [SecurityViolation]::new(
                            "CredentialExposure",
                            "Plaintext password conversion detected. Use Read-Host -AsSecureString instead.",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Check for hardcoded passwords
                $stringLiterals = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst]
                }, $true)
                
                foreach ($literal in $stringLiterals) {
                    $text = $literal.Value.ToLower()
                    if ($text -match 'password|pwd|secret|key' -and $literal.Value.Length -gt 8) {
                        $context = $literal.Parent.Extent.Text
                        if ($context -match 'password\s*=|pwd\s*=|secret\s*=') {
                            $violations += [SecurityViolation]::new(
                                "CredentialExposure",
                                "Potential hardcoded credential detected",
                                [SecuritySeverity]::Critical,
                                $literal.Extent.StartLineNumber,
                                $literal.Extent.Text
                            )
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 3: Command Injection
        $this.SecurityRules.Add([SecurityRule]::new(
            "CommandInjection",
            "Detects potential command injection vulnerabilities",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find Invoke-Expression calls
                $iexCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    ($args[0].GetCommandName() -eq 'Invoke-Expression' -or 
                     $args[0].GetCommandName() -eq 'iex')
                }, $true)
                
                foreach ($call in $iexCalls) {
                    # Check if the expression contains variables or parameters
                    if ($call.CommandElements.Count -gt 1) {
                        $expression = $call.CommandElements[1].Extent.Text
                        if ($expression -match '\$') {
                            $violations += [SecurityViolation]::new(
                                "CommandInjection",
                                "Potential command injection via Invoke-Expression with variables",
                                [SecuritySeverity]::Critical,
                                $call.Extent.StartLineNumber,
                                $call.Extent.Text
                            )
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 4: Certificate Validation
        $this.SecurityRules.Add([SecurityRule]::new(
            "CertificateValidation",
            "Validates certificate security practices",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Look for specific certificate validation bypasses
                # Pattern 1: ServerCertificateValidationCallback = { $true }
                $assignments = $Ast.FindAll({
                    $args[0] -is [AssignmentStatementAst]
                }, $true)
                
                foreach ($assignment in $assignments) {
                    $leftSide = $assignment.Left.Extent.Text
                    if ($leftSide -match 'ServerCertificateValidationCallback') {
                        $rightSide = $assignment.Right.Extent.Text
                        # Check if it's setting to { $true } or similar
                        if ($rightSide -match '^\s*\{\s*\$true\s*\}\s*$' -or $rightSide -match '^\s*\{\s*return\s+\$true\s*\}\s*$') {
                            $violations += [SecurityViolation]::new(
                                "CertificateValidation",
                                "Certificate validation callback set to always return true - bypasses certificate security",
                                [SecuritySeverity]::High,
                                $assignment.Extent.StartLineNumber,
                                $assignment.Extent.Text
                            )
                        }
                    }
                }
                
                # Pattern 2: CheckCertRevocationStatus = $false
                foreach ($assignment in $assignments) {
                    $leftSide = $assignment.Left.Extent.Text
                    if ($leftSide -match 'CheckCertRevocationStatus|CheckCertificateRevocationList') {
                        $rightSide = $assignment.Right.Extent.Text
                        if ($rightSide -match '\$false') {
                            $violations += [SecurityViolation]::new(
                                "CertificateValidation",
                                "Certificate revocation checking disabled - security risk",
                                [SecuritySeverity]::High,
                                $assignment.Extent.StartLineNumber,
                                $assignment.Extent.Text
                            )
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 5: Execution Policy Bypass
        $this.SecurityRules.Add([SecurityRule]::new(
            "ExecutionPolicyBypass",
            "Detects attempts to bypass PowerShell execution policy",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find Set-ExecutionPolicy with Unrestricted or Bypass
                $execPolicyCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'Set-ExecutionPolicy'
                }, $true)
                
                foreach ($call in $execPolicyCalls) {
                    $policyValue = $null
                    for ($i = 0; $i -lt $call.CommandElements.Count; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [StringConstantExpressionAst]) {
                            $value = $element.Value
                            if ($value -in @('Unrestricted', 'Bypass')) {
                                $policyValue = $value
                                break
                            }
                        }
                    }
                    
                    if ($policyValue) {
                        $violations += [SecurityViolation]::new(
                            "ExecutionPolicyBypass",
                            "Execution policy set to '$policyValue' - bypasses security controls",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Check for -ExecutionPolicy parameter in command line arguments
                $stringLiterals = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst]
                }, $true)
                
                foreach ($literal in $stringLiterals) {
                    if ($literal.Value -match '-ExecutionPolicy\s+(Bypass|Unrestricted)') {
                        $violations += [SecurityViolation]::new(
                            "ExecutionPolicyBypass",
                            "Command line execution policy bypass detected",
                            [SecuritySeverity]::Critical,
                            $literal.Extent.StartLineNumber,
                            $literal.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 6: Script Block Logging
        $this.SecurityRules.Add([SecurityRule]::new(
            "ScriptBlockLogging",
            "Detects disabling of security logging configuration",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find PSModuleAutoLoadingPreference = 'None'
                $assignments = $Ast.FindAll({
                    $args[0] -is [AssignmentStatementAst]
                }, $true)
                
                foreach ($assignment in $assignments) {
                    $leftSide = $assignment.Left.Extent.Text
                    if ($leftSide -match 'PSModuleAutoLoadingPreference') {
                        $rightSide = $assignment.Right.Extent.Text
                        if ($rightSide -match 'None') {
                            $violations += [SecurityViolation]::new(
                                "ScriptBlockLogging",
                                "Module auto-loading disabled - may bypass logging",
                                [SecuritySeverity]::High,
                                $assignment.Extent.StartLineNumber,
                                $assignment.Extent.Text
                            )
                        }
                    }
                    
                    # Check for disabling script block logging
                    if ($leftSide -match 'ScriptBlockLogging|EnableScriptBlockLogging') {
                        $rightSide = $assignment.Right.Extent.Text
                        if ($rightSide -match '\$false|0') {
                            $violations += [SecurityViolation]::new(
                                "ScriptBlockLogging",
                                "Script block logging disabled - security risk",
                                [SecuritySeverity]::High,
                                $assignment.Extent.StartLineNumber,
                                $assignment.Extent.Text
                            )
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 7: Unsafe PS Remoting
        $this.SecurityRules.Add([SecurityRule]::new(
            "UnsafePSRemoting",
            "Detects insecure PowerShell remoting configurations",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find Enable-PSRemoting with -Force
                $remotingCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -in @('Enable-PSRemoting', 'Enter-PSSession', 'New-PSSession')
                }, $true)
                
                foreach ($call in $remotingCalls) {
                    $commandName = $call.GetCommandName()
                    
                    # Check for -Force parameter in Enable-PSRemoting
                    if ($commandName -eq 'Enable-PSRemoting') {
                        foreach ($element in $call.CommandElements) {
                            if ($element -is [CommandParameterAst] -and $element.ParameterName -eq 'Force') {
                                $violations += [SecurityViolation]::new(
                                    "UnsafePSRemoting",
                                    "Enable-PSRemoting with -Force bypasses security prompts",
                                    [SecuritySeverity]::Critical,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                                break
                            }
                        }
                    }
                    
                    # Check for -UseSSL:$false in session commands
                    if ($commandName -in @('Enter-PSSession', 'New-PSSession')) {
                        $hasUseSSLFalse = $false
                        for ($i = 0; $i -lt $call.CommandElements.Count; $i++) {
                            $element = $call.CommandElements[$i]
                            if ($element -is [CommandParameterAst] -and $element.ParameterName -eq 'UseSSL') {
                                # Check if parameter has argument (e.g., -UseSSL:$false)
                                if ($element.Argument) {
                                    if ($element.Argument.Extent.Text -match '\$false') {
                                        $hasUseSSLFalse = $true
                                        break
                                    }
                                }
                                # Check if next element is $false (e.g., -UseSSL $false)
                                elseif ($i + 1 -lt $call.CommandElements.Count) {
                                    $nextElement = $call.CommandElements[$i + 1]
                                    if ($nextElement.Extent.Text -match '\$false') {
                                        $hasUseSSLFalse = $true
                                        break
                                    }
                                }
                            }
                        }
                        
                        if ($hasUseSSLFalse) {
                            $violations += [SecurityViolation]::new(
                                "UnsafePSRemoting",
                                "PowerShell remoting without SSL encryption - security risk",
                                [SecuritySeverity]::Critical,
                                $call.Extent.StartLineNumber,
                                $call.Extent.Text
                            )
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 8: Dangerous Modules
        $this.SecurityRules.Add([SecurityRule]::new(
            "DangerousModules",
            "Detects import of modules from untrusted sources",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find Import-Module calls
                $importCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'Import-Module'
                }, $true)
                
                foreach ($call in $importCalls) {
                    $hasVariable = $false
                    $hasExpression = $false
                    
                    # Check if module path contains variables or expressions
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [VariableExpressionAst]) {
                            $hasVariable = $true
                        } elseif ($element -is [SubExpressionAst] -or $element -is [ExpandableStringExpressionAst]) {
                            $hasExpression = $true
                        }
                    }
                    
                    if ($hasVariable -or $hasExpression) {
                        $violations += [SecurityViolation]::new(
                            "DangerousModules",
                            "Dynamic module import from variable or expression - validate source",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 9: PowerShell Version Downgrade
        $this.SecurityRules.Add([SecurityRule]::new(
            "PowerShellVersionDowngrade",
            "Detects PowerShell version downgrade attacks",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find powershell.exe with -version parameter
                $stringLiterals = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst]
                }, $true)
                
                foreach ($literal in $stringLiterals) {
                    if ($literal.Value -match 'powershell(.exe)?\s+-version\s+2') {
                        $violations += [SecurityViolation]::new(
                            "PowerShellVersionDowngrade",
                            "PowerShell v2 downgrade detected - bypasses modern security features",
                            [SecuritySeverity]::Critical,
                            $literal.Extent.StartLineNumber,
                            $literal.Extent.Text
                        )
                    }
                }
                
                # Check for Start-Process with PowerShell v2
                $startProcessCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'Start-Process'
                }, $true)
                
                foreach ($call in $startProcessCalls) {
                    $callText = $call.Extent.Text
                    if ($callText -match '-version\s+2') {
                        $violations += [SecurityViolation]::new(
                            "PowerShellVersionDowngrade",
                            "PowerShell v2 launch detected in Start-Process",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 10: Unsafe Deserialization
        $this.SecurityRules.Add([SecurityRule]::new(
            "UnsafeDeserialization",
            "Detects unsafe XML/CLIXML deserialization",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find Import-Clixml calls
                $clixmlCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'Import-Clixml'
                }, $true)
                
                foreach ($call in $clixmlCalls) {
                    # Check if path comes from variable or user input
                    $hasVariable = $false
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [VariableExpressionAst] -or $element -is [SubExpressionAst]) {
                            $hasVariable = $true
                            break
                        }
                    }
                    
                    if ($hasVariable) {
                        $violations += [SecurityViolation]::new(
                            "UnsafeDeserialization",
                            "Import-Clixml from untrusted source - code execution risk",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Check for ConvertFrom-Json with -Depth parameter (deep object graphs)
                $jsonCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'ConvertFrom-Json'
                }, $true)
                
                foreach ($call in $jsonCalls) {
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [CommandParameterAst] -and $element.ParameterName -eq 'Depth') {
                            $violations += [SecurityViolation]::new(
                                "UnsafeDeserialization",
                                "Deep JSON deserialization can cause DoS or memory issues",
                                [SecuritySeverity]::Medium,
                                $call.Extent.StartLineNumber,
                                $call.Extent.Text
                            )
                            break
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 11: Privilege Escalation
        $this.SecurityRules.Add([SecurityRule]::new(
            "PrivilegeEscalation",
            "Detects privilege escalation attempts",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find Start-Process with -Verb RunAs
                $startProcessCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'Start-Process'
                }, $true)
                
                foreach ($call in $startProcessCalls) {
                    $hasRunAs = $false
                    for ($i = 0; $i -lt $call.CommandElements.Count; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and $element.ParameterName -eq 'Verb') {
                            if ($i + 1 -lt $call.CommandElements.Count) {
                                $nextElement = $call.CommandElements[$i + 1]
                                if ($nextElement -is [StringConstantExpressionAst] -and $nextElement.Value -eq 'RunAs') {
                                    $hasRunAs = $true
                                    break
                                }
                            }
                        }
                    }
                    
                    if ($hasRunAs) {
                        $violations += [SecurityViolation]::new(
                            "PrivilegeEscalation",
                            "Privilege escalation via Start-Process -Verb RunAs - validate necessity",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 12: Script Injection
        $this.SecurityRules.Add([SecurityRule]::new(
            "ScriptInjection",
            "Detects dynamic script generation vulnerabilities",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find New-Module with dynamic content
                $moduleCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'New-Module'
                }, $true)
                
                foreach ($call in $moduleCalls) {
                    $hasScriptBlock = $false
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [ScriptBlockExpressionAst] -or $element -is [VariableExpressionAst]) {
                            $hasScriptBlock = $true
                            break
                        }
                    }
                    
                    if ($hasScriptBlock) {
                        $violations += [SecurityViolation]::new(
                            "ScriptInjection",
                            "Dynamic module creation - validate script content",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Find Add-Type with user input
                $addTypeCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'Add-Type'
                }, $true)
                
                foreach ($call in $addTypeCalls) {
                    $hasVariable = $false
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [VariableExpressionAst] -or $element -is [SubExpressionAst]) {
                            $hasVariable = $true
                            break
                        }
                    }
                    
                    if ($hasVariable) {
                        $violations += [SecurityViolation]::new(
                            "ScriptInjection",
                            "Add-Type with dynamic content - code injection risk",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Find [scriptblock]::Create with variables
                $scriptBlockCreate = $Ast.FindAll({
                    $args[0] -is [MemberExpressionAst] -and
                    $args[0].Member.Value -eq 'Create'
                }, $true)
                
                foreach ($member in $scriptBlockCreate) {
                    if ($member.Expression -is [TypeExpressionAst] -and 
                        $member.Expression.TypeName.Name -eq 'scriptblock') {
                        $violations += [SecurityViolation]::new(
                            "ScriptInjection",
                            "[scriptblock]::Create() detected - potential constrained mode bypass",
                            [SecuritySeverity]::Critical,
                            $member.Extent.StartLineNumber,
                            $member.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 13: Unsafe Reflection
        $this.SecurityRules.Add([SecurityRule]::new(
            "UnsafeReflection",
            "Detects unsafe .NET reflection usage",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find Assembly::LoadFrom, Assembly::Load, or Assembly::LoadFile
                $memberAccess = $Ast.FindAll({
                    $args[0] -is [MemberExpressionAst] -and
                    $args[0].Member -and
                    $args[0].Member.Value -in @('LoadFrom', 'Load', 'LoadFile', 'Assembly')
                }, $true)
                
                foreach ($member in $memberAccess) {
                    if ($member.Member.Value -in @('LoadFrom', 'Load', 'LoadFile')) {
                        if ($member.Expression -is [TypeExpressionAst] -and 
                            $member.Expression.TypeName.Name -match 'Assembly') {
                            $violations += [SecurityViolation]::new(
                                "UnsafeReflection",
                                "Unsafe assembly loading via reflection - validate source",
                                [SecuritySeverity]::High,
                                $member.Extent.StartLineNumber,
                                $member.Extent.Text
                            )
                        }
                    }
                    elseif ($member.Member.Value -eq 'Assembly') {
                        # Only flag if it's part of GetType().Assembly pattern
                        if ($member.Expression -is [MemberExpressionAst] -and
                            $member.Expression.Member -and
                            $member.Expression.Member.Value -eq 'GetType') {
                            $violations += [SecurityViolation]::new(
                                "UnsafeReflection",
                                "Direct assembly access via GetType().Assembly - review security implications",
                                [SecuritySeverity]::Medium,
                                $member.Extent.StartLineNumber,
                                $member.Extent.Text
                            )
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 14: PowerShell Constrained Mode
        $this.SecurityRules.Add([SecurityRule]::new(
            "PowerShellConstrainedMode",
            "Detects patterns that may break in constrained language mode",
            [SecuritySeverity]::Medium,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find Add-Type usage
                $addTypeCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'Add-Type'
                }, $true)
                
                if ($addTypeCalls.Count -gt 0) {
                    $violations += [SecurityViolation]::new(
                        "PowerShellConstrainedMode",
                        "Add-Type not allowed in constrained language mode",
                        [SecuritySeverity]::Medium,
                        $addTypeCalls[0].Extent.StartLineNumber,
                        $addTypeCalls[0].Extent.Text
                    )
                }
                
                # Find New-Object with COM objects
                $newObjectCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'New-Object'
                }, $true)
                
                foreach ($call in $newObjectCalls) {
                    $hasComObject = $false
                    for ($i = 0; $i -lt $call.CommandElements.Count; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and $element.ParameterName -eq 'ComObject') {
                            $hasComObject = $true
                            break
                        }
                    }
                    
                    if ($hasComObject) {
                        $violations += [SecurityViolation]::new(
                            "PowerShellConstrainedMode",
                            "COM object creation not allowed in constrained mode",
                            [SecuritySeverity]::Medium,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 15: Unsafe File Inclusion
        $this.SecurityRules.Add([SecurityRule]::new(
            "UnsafeFileInclusion",
            "Detects dot-sourcing of untrusted scripts",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find dot-sourcing operations
                $dotSourceExpressions = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and $args[0].InvocationOperator -eq [TokenKind]::Dot
                }, $true)
                
                foreach ($dotSource in $dotSourceExpressions) {
                    # Check if the sourced file path contains variables or dynamic content
                    $hasDynamicPath = $false
                    foreach ($element in $dotSource.CommandElements) {
                        if ($element -is [VariableExpressionAst] -or 
                            $element -is [SubExpressionAst] -or
                            $element -is [ParenExpressionAst] -or
                            $element -is [ExpandableStringExpressionAst]) {
                            $hasDynamicPath = $true
                            break
                        }
                    }
                    
                    if ($hasDynamicPath) {
                        $violations += [SecurityViolation]::new(
                            "UnsafeFileInclusion",
                            "Dot-sourcing script from variable or dynamic path - validate source",
                            [SecuritySeverity]::Critical,
                            $dotSource.Extent.StartLineNumber,
                            $dotSource.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 16: PowerShell Web Requests
        $this.SecurityRules.Add([SecurityRule]::new(
            "PowerShellWebRequests",
            "Detects web requests without proper certificate validation",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find Invoke-WebRequest and Invoke-RestMethod calls
                $webCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -in @('Invoke-WebRequest', 'Invoke-RestMethod')
                }, $true)
                
                foreach ($call in $webCalls) {
                    $hasSkipCertCheck = $false
                    
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -in @('SkipCertificateCheck', 'SkipCertCheck')) {
                            $hasSkipCertCheck = $true
                            break
                        }
                    }
                    
                    if ($hasSkipCertCheck) {
                        $violations += [SecurityViolation]::new(
                            "PowerShellWebRequests",
                            "Web request with certificate validation disabled",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))
    }

    [PSCustomObject] AnalyzeScript([string]$ScriptPath) {
        if (-not (Test-Path $ScriptPath)) {
            throw "Script file not found: $ScriptPath"
        }

        $fileInfo = Get-Item $ScriptPath
        if ($fileInfo.Length -gt $this.Configuration.MaxFileSize) {
            throw "File too large: $($fileInfo.Length) bytes exceeds limit of $($this.Configuration.MaxFileSize) bytes"
        }

        try {
            # Parse the script
            $tokens = $null
            $errors = $null
            $ast = [Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
            
            if ($errors.Count -gt 0) {
                Write-Warning "Parse errors in $ScriptPath`: $($errors -join '; ')"
            }

            # Run security rules
            $allViolations = @()
            
            $rules = $this.SecurityRules + $this.CodingRules
            foreach ($rule in $rules) {
                try {
                    $ruleViolations = $rule.Evaluate($ast, $ScriptPath)
                    $allViolations += $ruleViolations
                } catch {
                    Write-Warning "Rule $($rule.Name) failed: $($_.Exception.Message)"
                }
            }

            return [PSCustomObject]@{
                FilePath = $ScriptPath
                Violations = $allViolations
                ParseErrors = $errors
                RulesExecuted = $rules.Count
                Timestamp = Get-Date
            }
        } catch {
            throw "Analysis failed for $ScriptPath`: $($_.Exception.Message)"
        }
    }

    [bool] IsPathExcluded([string]$FilePath, [string]$WorkspacePath) {
        # Normalize paths for comparison
        $normalizedFilePath = $FilePath.Replace('\', '/').TrimStart('./')
        $normalizedWorkspacePath = $WorkspacePath.Replace('\', '/').TrimEnd('/')
        
        # Get relative path from workspace
        if ($normalizedFilePath.StartsWith($normalizedWorkspacePath)) {
            $relativePath = $normalizedFilePath.Substring($normalizedWorkspacePath.Length).TrimStart('/')
        } else {
            $relativePath = $normalizedFilePath
        }
        
        # Check against exclusion patterns
        foreach ($pattern in $this.Configuration.ExcludedPaths) {
            $normalizedPattern = $pattern.Replace('\', '/')
            
            # Simple wildcard matching
            if ($normalizedPattern.Contains('*')) {
                # Convert pattern to regex
                $regexPattern = '^' + [regex]::Escape($normalizedPattern).Replace('\*', '.*') + '.*'
                if ($relativePath -match $regexPattern) {
                    return $true
                }
            } else {
                # Exact match or starts with pattern
                if ($relativePath -eq $normalizedPattern -or $relativePath.StartsWith($normalizedPattern + '/')) {
                    return $true
                }
            }
        }
        
        return $false
    }

    [PSCustomObject] AnalyzeWorkspace([string]$WorkspacePath) {
        $scriptFiles = Get-ChildItem -Path $WorkspacePath -Recurse -Include "*.ps1", "*.psm1", "*.psd1" -ErrorAction SilentlyContinue | 
                      Where-Object { $_.Length -le $this.Configuration.MaxFileSize }
        
        $allResults = @()
        $totalViolations = 0
        $excludedCount = 0
        
        foreach ($file in $scriptFiles) {
            # Check if file should be excluded
            if ($this.IsPathExcluded($file.FullName, $WorkspacePath)) {
                $excludedCount++
                Write-Verbose "Excluding file from analysis: $($file.FullName)"
                continue
            }
            
            try {
                $result = $this.AnalyzeScript($file.FullName)
                $allResults += $result
                $totalViolations += $result.Violations.Count
                
                Write-Progress -Activity "Analyzing PowerShell Files" -Status $file.Name -PercentComplete (($allResults.Count / $scriptFiles.Count) * 100)
            } catch {
                Write-Warning "Failed to analyze $($file.FullName): $($_.Exception.Message)"
            }
        }
        
        Write-Progress -Activity "Analyzing PowerShell Files" -Completed
        
        if ($excludedCount -gt 0) {
            Write-Host "Excluded $excludedCount files from analysis based on configuration"
        }

        return [PSCustomObject]@{
            WorkspacePath = $WorkspacePath
            FilesAnalyzed = $allResults.Count
            FilesExcluded = $excludedCount
            TotalViolations = $totalViolations
            Results = $allResults
            Summary = $this.GenerateSummary($allResults)
            Timestamp = Get-Date
        }
    }

    [hashtable] GenerateSummary([array]$Results) {
        $summary = @{
            TotalFiles = $Results.Count
            TotalViolations = 0
            BySeverity = @{
                Critical = 0
                High = 0
                Medium = 0
                Low = 0
            }
            ByCategory = @{}
            TopIssues = @()
        }

        foreach ($result in $Results) {
            if ($result.Violations) {
                foreach ($violation in $result.Violations) {
                    if ($violation) {
                        $summary.TotalViolations++
                        $severityStr = if ($violation.Severity) { $violation.Severity.ToString() } else { 'Low' }
                        if ($summary.BySeverity.ContainsKey($severityStr)) {
                            $summary.BySeverity[$severityStr]++
                        }
                        
                        $violationName = if ($violation.Name) { $violation.Name } else { 'Unknown' }
                        if (-not $summary.ByCategory.ContainsKey($violationName)) {
                            $summary.ByCategory[$violationName] = 0
                        }
                        $summary.ByCategory[$violationName]++
                    }
                }
            }
        }

        $summary.TopIssues = $summary.ByCategory.GetEnumerator() | 
                            Sort-Object Value -Descending | 
                            Select-Object -First 5 |
                            ForEach-Object { @{ Rule = $_.Key; Count = $_.Value } }

        return $summary
    }
}

# Helper functions for external use
function New-SecurityAnalyzer {
    <#
    .SYNOPSIS
        Creates a new PowerShell Security Analyzer instance
    #>
    return [PowerShellSecurityAnalyzer]::new()
}

function Invoke-SecurityAnalysis {
    <#
    .SYNOPSIS
        Analyzes a PowerShell script for security violations
    .PARAMETER ScriptPath
        Path to the PowerShell script to analyze
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ScriptPath
    )
    
    $analyzer = [PowerShellSecurityAnalyzer]::new()
    return $analyzer.AnalyzeScript($ScriptPath)
}

function Invoke-WorkspaceAnalysis {
    <#
    .SYNOPSIS
        Analyzes all PowerShell scripts in a workspace
    .PARAMETER WorkspacePath
        Path to the workspace directory
    #>
    param(
        [Parameter(Mandatory)]
        [string]$WorkspacePath
    )
    
    $analyzer = [PowerShellSecurityAnalyzer]::new()
    return $analyzer.AnalyzeWorkspace($WorkspacePath)
}

# Export module members
Export-ModuleMember -Function New-SecurityAnalyzer, Invoke-SecurityAnalysis, Invoke-WorkspaceAnalysis
