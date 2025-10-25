#Requires -Version 7.0

<#
.SYNOPSIS
    PowerShell Security Analyzer Module for PowerShield
.DESCRIPTION
    Analyzes PowerShell scripts for security vulnerabilities and provides detailed reports.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
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
            if ($violation) {
                $violation.FilePath = $filePath
                $violation.RuleId = $this.Name
            }
        }
        return $violations
    }
}

class PowerShellSecurityAnalyzer {
    [List[SecurityRule]]$SecurityRules
    [List[SecurityRule]]$CodingRules
    [hashtable]$Configuration
    [object]$PowerShieldConfig  # PowerShieldConfiguration object
    [object]$SuppressionParser  # SuppressionParser object

    PowerShellSecurityAnalyzer() {
        $this.SecurityRules = [List[SecurityRule]]::new()
        $this.CodingRules = [List[SecurityRule]]::new()
        $this.Configuration = @{
            EnableParallelAnalysis = $true
            MaxFileSize = 10MB
            TimeoutSeconds = 30
            ExcludedPaths = @('tests/TestScripts', '*/TestScripts', 'test/*', 'tests/*', 'src/*', 'scripts/*')
        }
        $this.PowerShieldConfig = $null
        $this.SuppressionParser = $null
        $this.InitializeDefaultRules()
    }

    PowerShellSecurityAnalyzer([object]$pstsConfig) {
        $this.SecurityRules = [List[SecurityRule]]::new()
        $this.CodingRules = [List[SecurityRule]]::new()
        $this.PowerShieldConfig = $pstsConfig
        
        # Merge PowerShield config into legacy Configuration
        $this.Configuration = @{
            EnableParallelAnalysis = $pstsConfig.Analysis.parallel_analysis
            MaxFileSize = $pstsConfig.Analysis.max_file_size
            TimeoutSeconds = $pstsConfig.Analysis.timeout_seconds
            ExcludedPaths = $pstsConfig.Analysis.exclude_paths
        }
        
        # Initialize suppression parser if configured
        if ($pstsConfig.Suppressions) {
            try {
                # Dynamically load SuppressionParser module if available
                $modulePath = Join-Path $PSScriptRoot 'SuppressionParser.psm1'
                if (Test-Path $modulePath) {
                    Import-Module $modulePath -Force -ErrorAction Stop
                    $this.SuppressionParser = New-SuppressionParser `
                        -RequireJustification $pstsConfig.Suppressions.require_justification `
                        -MaxDurationDays $pstsConfig.Suppressions.max_duration_days `
                        -AllowPermanent $pstsConfig.Suppressions.allow_permanent
                }
            } catch {
                Write-Warning "Failed to initialize suppression parser: $_"
            }
        }
        
        $this.InitializeDefaultRules()
    }

    [void] LoadConfiguration([string]$workspacePath) {
        try {
            # Load ConfigLoader module if available
            $modulePath = Join-Path $PSScriptRoot 'ConfigLoader.psm1'
            if (Test-Path $modulePath) {
                Import-Module $modulePath -Force -ErrorAction Stop
                $this.PowerShieldConfig = Import-PowerShieldConfiguration -WorkspacePath $workspacePath
                
                # Update Configuration
                $this.Configuration.EnableParallelAnalysis = $this.PowerShieldConfig.Analysis.parallel_analysis
                $this.Configuration.MaxFileSize = $this.PowerShieldConfig.Analysis.max_file_size
                $this.Configuration.TimeoutSeconds = $this.PowerShieldConfig.Analysis.timeout_seconds
                $this.Configuration.ExcludedPaths = $this.PowerShieldConfig.Analysis.exclude_paths
                
                Write-Verbose "Loaded PowerShield configuration from $workspacePath"
            }
        } catch {
            Write-Warning "Failed to load PowerShield configuration: $_"
        }
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

        # ===== PHASE 1.5B: GENERAL SECURITY RULES =====

        # Network Security Rules

        # Rule 17: Insecure HTTP Detection
        $this.SecurityRules.Add([SecurityRule]::new(
            "InsecureHTTP",
            "Detects unencrypted HTTP requests in web cmdlets",
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
                    # Check for HTTP URIs (not HTTPS)
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [StringConstantExpressionAst] -and 
                            $element.Value -match '^http://') {
                            $violations += [SecurityViolation]::new(
                                "InsecureHTTP",
                                "Unencrypted HTTP request detected. Use HTTPS instead.",
                                [SecuritySeverity]::High,
                                $call.Extent.StartLineNumber,
                                $call.Extent.Text
                            )
                        }
                    }
                    
                    # Check for -Uri parameter with HTTP
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and $element.ParameterName -eq 'Uri') {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement -is [StringConstantExpressionAst] -and 
                                $nextElement.Value -match '^http://') {
                                $violations += [SecurityViolation]::new(
                                    "InsecureHTTP",
                                    "Unencrypted HTTP URI in -Uri parameter. Use HTTPS instead.",
                                    [SecuritySeverity]::High,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 18: Weak TLS Configuration
        $this.SecurityRules.Add([SecurityRule]::new(
            "WeakTLS",
            "Detects weak TLS/SSL configuration and protocol downgrades",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Check for TLS protocol downgrades
                $tlsAssignments = $Ast.FindAll({
                    $args[0] -is [AssignmentStatementAst] -and
                    $args[0].Left.VariablePath.UserPath -match 'SecurityProtocol'
                }, $true)
                
                foreach ($assignment in $tlsAssignments) {
                    if ($assignment.Right -is [VariableExpressionAst] -and
                        $assignment.Right.VariablePath.UserPath -match 'Ssl3|Tls$|Tls10|Tls11') {
                        $violations += [SecurityViolation]::new(
                            "WeakTLS",
                            "Weak TLS/SSL protocol configuration detected. Use TLS 1.2 or higher.",
                            [SecuritySeverity]::High,
                            $assignment.Extent.StartLineNumber,
                            $assignment.Extent.Text
                        )
                    }
                }
                
                # Check for explicit weak protocol usage
                $protocolRefs = $Ast.FindAll({
                    $args[0] -is [MemberExpressionAst] -and
                    $args[0].Member.Value -match 'Ssl3|Tls$|Tls10|Tls11'
                }, $true)
                
                foreach ($ref in $protocolRefs) {
                    $violations += [SecurityViolation]::new(
                        "WeakTLS",
                        "Reference to weak TLS/SSL protocol detected: $($ref.Member.Value)",
                        [SecuritySeverity]::High,
                        $ref.Extent.StartLineNumber,
                        $ref.Extent.Text
                    )
                }
                
                return $violations
            }
        ))

        # Rule 19: Hardcoded URLs
        $this.SecurityRules.Add([SecurityRule]::new(
            "HardcodedURLs",
            "Detects hardcoded production URLs and endpoints",
            [SecuritySeverity]::Medium,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Production URL patterns
                $prodPatterns = @(
                    'api\.prod\.',
                    'prod\.',
                    'production\.',
                    'live\.',
                    'www\.',
                    '\.com/',
                    '\.net/',
                    '\.org/'
                )
                
                # Find string literals that look like URLs
                $strings = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst]
                }, $true)
                
                foreach ($string in $strings) {
                    if ($string.Value -match '^https?://') {
                        foreach ($pattern in $prodPatterns) {
                            if ($string.Value -match $pattern) {
                                $violations += [SecurityViolation]::new(
                                    "HardcodedURLs",
                                    "Hardcoded production URL detected. Consider using configuration variables.",
                                    [SecuritySeverity]::Medium,
                                    $string.Extent.StartLineNumber,
                                    $string.Extent.Text
                                )
                                break
                            }
                        }
                    }
                }
                
                return $violations
            }
        ))

        # File System Security Rules

        # Rule 20: Path Traversal Detection
        $this.SecurityRules.Add([SecurityRule]::new(
            "PathTraversal",
            "Detects directory traversal vulnerabilities",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find path operations with traversal patterns
                $strings = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst]
                }, $true)
                
                foreach ($string in $strings) {
                    if ($string.Value -match '\.\.[/\\]' -or $string.Value -match '[/\\]\.\.[/\\]') {
                        $violations += [SecurityViolation]::new(
                            "PathTraversal",
                            "Directory traversal pattern detected: $($string.Value)",
                            [SecuritySeverity]::High,
                            $string.Extent.StartLineNumber,
                            $string.Extent.Text
                        )
                    }
                }
                
                # Check for dangerous path operations
                $pathCmdlets = @('Join-Path', 'Resolve-Path', 'Get-ChildItem', 'Set-Location')
                $pathCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -in $pathCmdlets
                }, $true)
                
                foreach ($call in $pathCalls) {
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [StringConstantExpressionAst] -and
                            ($element.Value -match '\.\.[/\\]' -or $element.Value -match '[/\\]\.\.[/\\]')) {
                            $violations += [SecurityViolation]::new(
                                "PathTraversal",
                                "Directory traversal in path cmdlet: $($call.GetCommandName())",
                                [SecuritySeverity]::High,
                                $call.Extent.StartLineNumber,
                                $call.Extent.Text
                            )
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 21: Unsafe File Permissions
        $this.SecurityRules.Add([SecurityRule]::new(
            "UnsafeFilePermissions",
            "Detects overly permissive file/folder permissions",
            [SecuritySeverity]::Medium,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Check Set-Acl and icacls usage
                $aclCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -in @('Set-Acl', 'icacls')
                }, $true)
                
                foreach ($call in $aclCalls) {
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [StringConstantExpressionAst]) {
                            # Check for overly permissive permissions
                            if ($element.Value -match 'Everyone.*Full|Users.*Full|.*777|.*666') {
                                $violations += [SecurityViolation]::new(
                                    "UnsafeFilePermissions",
                                    "Overly permissive file permissions detected",
                                    [SecuritySeverity]::Medium,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                # Check .NET FileSystemAccessRule usage
                $fsRules = $Ast.FindAll({
                    $args[0] -is [TypeExpressionAst] -and
                    $args[0].TypeName.Name -match 'FileSystemAccessRule'
                }, $true)
                
                foreach ($rule in $fsRules) {
                    $violations += [SecurityViolation]::new(
                        "UnsafeFilePermissions",
                        "Manual file system access rule creation detected. Review permissions carefully.",
                        [SecuritySeverity]::Medium,
                        $rule.Extent.StartLineNumber,
                        $rule.Extent.Text
                    )
                }
                
                return $violations
            }
        ))

        # Rule 22: Temporary File Exposure
        $this.SecurityRules.Add([SecurityRule]::new(
            "TempFileExposure",
            "Detects unsafe temporary file handling",
            [SecuritySeverity]::Medium,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Check for temp file operations
                $tempVars = @('$env:TEMP', '$env:TMP', '$env:TMPDIR')
                $tempFunctions = @('New-TemporaryFile', '[System.IO.Path]::GetTempFileName()')
                
                # Find temp directory usage
                $variables = $Ast.FindAll({
                    $args[0] -is [VariableExpressionAst]
                }, $true)
                
                foreach ($var in $variables) {
                    if ($var.VariablePath.UserPath -in @('env:TEMP', 'env:TMP', 'env:TMPDIR')) {
                        $violations += [SecurityViolation]::new(
                            "TempFileExposure",
                            "Temporary directory usage detected. Ensure proper cleanup and permissions.",
                            [SecuritySeverity]::Medium,
                            $var.Extent.StartLineNumber,
                            $var.Extent.Text
                        )
                    }
                }
                
                # Check for New-TemporaryFile usage
                $tempCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'New-TemporaryFile'
                }, $true)
                
                foreach ($call in $tempCalls) {
                    $violations += [SecurityViolation]::new(
                        "TempFileExposure",
                        "Temporary file creation detected. Ensure proper cleanup and secure permissions.",
                        [SecuritySeverity]::Medium,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                return $violations
            }
        ))

        # Rule 23: Unsafe File Operations
        $this.SecurityRules.Add([SecurityRule]::new(
            "UnsafeFileOperations",
            "Detects dangerous file operations without validation",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Dangerous file operations
                $dangerousOps = @('Remove-Item', 'Delete', 'Copy-Item', 'Move-Item', 'Rename-Item')
                
                $fileCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -in $dangerousOps
                }, $true)
                
                foreach ($call in $fileCalls) {
                    # Check for wildcard usage without -WhatIf
                    $hasWildcard = $false
                    $hasWhatIf = $false
                    
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [StringConstantExpressionAst] -and
                            $element.Value -match '\*') {
                            $hasWildcard = $true
                        }
                        if ($element -is [CommandParameterAst] -and
                            $element.ParameterName -eq 'WhatIf') {
                            $hasWhatIf = $true
                        }
                    }
                    
                    if ($hasWildcard -and -not $hasWhatIf) {
                        $violations += [SecurityViolation]::new(
                            "UnsafeFileOperations",
                            "Wildcard file operation without -WhatIf protection: $($call.GetCommandName())",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                    
                    # Check for operations on system directories
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [StringConstantExpressionAst] -and
                            ($element.Value -match '^C:\\Windows' -or 
                             $element.Value -match '^C:\\Program Files' -or
                             $element.Value -match '^/bin|^/usr|^/etc|^/var')) {
                            $violations += [SecurityViolation]::new(
                                "UnsafeFileOperations",
                                "File operation on system directory detected: $($element.Value)",
                                [SecuritySeverity]::High,
                                $call.Extent.StartLineNumber,
                                $call.Extent.Text
                            )
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Registry Security Rules

        # Rule 24: Dangerous Registry Modifications
        $this.SecurityRules.Add([SecurityRule]::new(
            "DangerousRegistryModifications",
            "Detects unsafe registry modifications affecting security settings",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Registry cmdlets
                $regCmdlets = @('Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-Item', 'New-Item')
                
                $regCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -in $regCmdlets
                }, $true)
                
                foreach ($call in $regCalls) {
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [StringConstantExpressionAst]) {
                            # Check for dangerous registry paths
                            $dangerousPaths = @(
                                'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                                'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                                'HKLM:\\SYSTEM\\CurrentControlSet\\Services',
                                'HKLM:\\SOFTWARE\\Policies',
                                'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies'
                            )
                            
                            foreach ($path in $dangerousPaths) {
                                if ($element.Value -match [regex]::Escape($path)) {
                                    $violations += [SecurityViolation]::new(
                                        "DangerousRegistryModifications",
                                        "Modification to security-sensitive registry path: $($element.Value)",
                                        [SecuritySeverity]::High,
                                        $call.Extent.StartLineNumber,
                                        $call.Extent.Text
                                    )
                                }
                            }
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 25: Registry Credentials
        $this.SecurityRules.Add([SecurityRule]::new(
            "RegistryCredentials",
            "Detects credentials stored in registry keys",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Registry operations
                $regCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -in @('Set-ItemProperty', 'New-ItemProperty')
                }, $true)
                
                foreach ($call in $regCalls) {
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [StringConstantExpressionAst]) {
                            # Check for credential-related property names
                            if ($element.Value -match 'password|pwd|secret|key|token|credential|auth') {
                                $violations += [SecurityViolation]::new(
                                    "RegistryCredentials",
                                    "Potential credential storage in registry detected: $($element.Value)",
                                    [SecuritySeverity]::Critical,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 26: Privileged Registry Access
        $this.SecurityRules.Add([SecurityRule]::new(
            "PrivilegedRegistryAccess",
            "Detects unnecessary privileged registry operations",
            [SecuritySeverity]::Medium,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Check for HKLM operations that might need privileges
                $regCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -match 'Registry|Item'
                }, $true)
                
                foreach ($call in $regCalls) {
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [StringConstantExpressionAst] -and
                            $element.Value -match '^HKLM:') {
                            $violations += [SecurityViolation]::new(
                                "PrivilegedRegistryAccess",
                                "HKEY_LOCAL_MACHINE registry access detected. Consider if privileges are necessary.",
                                [SecuritySeverity]::Medium,
                                $call.Extent.StartLineNumber,
                                $call.Extent.Text
                            )
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Data Security Rules

        # Rule 27: SQL Injection Detection
        $this.SecurityRules.Add([SecurityRule]::new(
            "SQLInjection",
            "Detects unsafe database query construction",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # SQL-related cmdlets and operations
                $sqlCmdlets = @('Invoke-Sqlcmd', 'Invoke-SqlCommand')
                
                $sqlCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -in $sqlCmdlets
                }, $true)
                
                foreach ($call in $sqlCalls) {
                    # Check for string concatenation in SQL queries
                    $hasConcat = $false
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [BinaryExpressionAst] -and
                            $element.Operator -eq 'Plus') {
                            $hasConcat = $true
                        }
                    }
                    
                    if ($hasConcat) {
                        $violations += [SecurityViolation]::new(
                            "SQLInjection",
                            "String concatenation in SQL command detected. Use parameterized queries.",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Check for dangerous SQL patterns in strings
                $strings = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst]
                }, $true)
                
                foreach ($string in $strings) {
                    if ($string.Value -match "INSERT INTO.*VALUES.*\+|UPDATE.*SET.*\+|DELETE FROM.*WHERE.*\+") {
                        $violations += [SecurityViolation]::new(
                            "SQLInjection",
                            "Dynamic SQL construction pattern detected in string literal",
                            [SecuritySeverity]::Critical,
                            $string.Extent.StartLineNumber,
                            $string.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 28: LDAP Injection Detection
        $this.SecurityRules.Add([SecurityRule]::new(
            "LDAPInjection",
            "Detects unsafe directory service queries",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # LDAP-related operations
                $ldapCmdlets = @('Get-ADUser', 'Get-ADGroup', 'Get-ADObject')
                
                $ldapCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -in $ldapCmdlets
                }, $true)
                
                foreach ($call in $ldapCalls) {
                    # Check for -Filter parameter with concatenation
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and $element.ParameterName -eq 'Filter') {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement -is [BinaryExpressionAst] -and
                                $nextElement.Operator -eq 'Plus') {
                                $violations += [SecurityViolation]::new(
                                    "LDAPInjection",
                                    "String concatenation in LDAP filter detected. Use parameterized filters.",
                                    [SecuritySeverity]::High,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                # Check for LDAP filter patterns in strings
                $strings = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst]
                }, $true)
                
                foreach ($string in $strings) {
                    if ($string.Value -match "\([a-zA-Z]+=[^)]*\+[^)]*\)" -and
                        $string.Value -match "cn=|ou=|dc=|uid=|mail=") {
                        $violations += [SecurityViolation]::new(
                            "LDAPInjection",
                            "Dynamic LDAP filter construction detected in string literal",
                            [SecuritySeverity]::High,
                            $string.Extent.StartLineNumber,
                            $string.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 29: XML Security Vulnerabilities
        $this.SecurityRules.Add([SecurityRule]::new(
            "XMLSecurity",
            "Detects XXE and unsafe XML parsing vulnerabilities",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # XML-related types and operations
                $xmlTypes = @('System.Xml.XmlDocument', 'System.Xml.XmlReader', 'System.Xml.XPath.XPathDocument')
                
                $xmlUsage = $Ast.FindAll({
                    $args[0] -is [TypeExpressionAst] -and
                    $args[0].TypeName.Name -in $xmlTypes
                }, $true)
                
                foreach ($usage in $xmlUsage) {
                    $violations += [SecurityViolation]::new(
                        "XMLSecurity",
                        "XML parser usage detected. Ensure DTD processing is disabled to prevent XXE attacks.",
                        [SecuritySeverity]::High,
                        $usage.Extent.StartLineNumber,
                        $usage.Extent.Text
                    )
                }
                
                # Check for XML loading operations
                $xmlCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -in @('Load', 'LoadXml')
                }, $true)
                
                foreach ($call in $xmlCalls) {
                    $violations += [SecurityViolation]::new(
                        "XMLSecurity",
                        "XML loading operation detected. Review for XXE vulnerabilities.",
                        [SecuritySeverity]::High,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                return $violations
            }
        ))

        # Rule 30: Log Injection Detection
        $this.SecurityRules.Add([SecurityRule]::new(
            "LogInjection",
            "Detects unsafe logging that could lead to log injection",
            [SecuritySeverity]::Medium,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Logging cmdlets and operations
                $logCmdlets = @('Write-Host', 'Write-Output', 'Write-Information', 'Write-Verbose', 'Write-Debug', 'Add-Content', 'Out-File')
                
                $logCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -in $logCmdlets
                }, $true)
                
                foreach ($call in $logCalls) {
                    # Check for variable or expression content that could be user input
                    foreach ($element in $call.CommandElements) {
                        if ($element -is [VariableExpressionAst] -and
                            $element.VariablePath.UserPath -match 'input|user|param|arg|request') {
                            $violations += [SecurityViolation]::new(
                                "LogInjection",
                                "Direct logging of potentially user-controlled input: $($element.VariablePath.UserPath)",
                                [SecuritySeverity]::Medium,
                                $call.Extent.StartLineNumber,
                                $call.Extent.Text
                            )
                        }
                        
                        if ($element -is [BinaryExpressionAst] -and
                            $element.Operator -eq 'Plus') {
                            $violations += [SecurityViolation]::new(
                                "LogInjection",
                                "String concatenation in logging operation. Sanitize user input before logging.",
                                [SecuritySeverity]::Medium,
                                $call.Extent.StartLineNumber,
                                $call.Extent.Text
                            )
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Phase 1.5C-A: Advanced PowerShell Security Rules - Immediate Priority

        # Rule 31: AMSI Evasion Detection
        $this.SecurityRules.Add([SecurityRule]::new(
            "AMSIEvasion",
            "Detects Anti-Malware Scan Interface (AMSI) bypass attempts",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: Direct AMSI bypass via AmsiUtils
                $amsiBypass = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst] -and 
                    $args[0].Value -match 'AmsiUtils|amsiInitFailed|amsiContext'
                }, $true)
                
                foreach ($bypass in $amsiBypass) {
                    $violations += [SecurityViolation]::new(
                        "AMSIEvasion",
                        "Direct AMSI bypass attempt detected: $($bypass.Value)",
                        [SecuritySeverity]::Critical,
                        $bypass.Extent.StartLineNumber,
                        $bypass.Extent.Text
                    )
                }
                
                # Pattern 2: Reflection-based AMSI bypass
                $reflectionBypass = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -match 'GetField|GetType' -and
                    $args[0].Extent.Text -match 'amsi|AMSI'
                }, $true)
                
                foreach ($bypass in $reflectionBypass) {
                    $violations += [SecurityViolation]::new(
                        "AMSIEvasion",
                        "Reflection-based AMSI bypass detected",
                        [SecuritySeverity]::Critical,
                        $bypass.Extent.StartLineNumber,
                        $bypass.Extent.Text
                    )
                }
                
                # Pattern 3: Assembly patching for AMSI bypass
                $assemblyPatching = $Ast.FindAll({
                    $args[0] -is [MemberExpressionAst] -and 
                    $args[0].Member.Value -match 'SetValue|WriteInt32' -and
                    $args[0].Extent.Text -match 'amsi|AMSI'
                }, $true)
                
                foreach ($patch in $assemblyPatching) {
                    $violations += [SecurityViolation]::new(
                        "AMSIEvasion",
                        "Memory patching for AMSI bypass detected",
                        [SecuritySeverity]::Critical,
                        $patch.Extent.StartLineNumber,
                        $patch.Extent.Text
                    )
                }
                
                # Pattern 4: PowerShell variable obfuscation for AMSI
                $obfuscation = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst] -and 
                    ($args[0].Value -match '\[char\].*\+.*\[char\]' -or
                     $args[0].Value -match '\$\(.*\[char\].*\)' -or
                     $args[0].Value -match 'iex.*char.*join')
                }, $true)
                
                foreach ($obf in $obfuscation) {
                    if ($obf.Extent.Text -match 'amsi|management\.automation') {
                        $violations += [SecurityViolation]::new(
                            "AMSIEvasion",
                            "Obfuscated AMSI bypass attempt detected",
                            [SecuritySeverity]::Critical,
                            $obf.Extent.StartLineNumber,
                            $obf.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 32: ETW Evasion Detection  
        $this.SecurityRules.Add([SecurityRule]::new(
            "ETWEvasion",
            "Detects Event Tracing for Windows (ETW) manipulation and bypass attempts",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: ScriptBlock logging bypass
                $scriptBlockBypass = $Ast.FindAll({
                    $args[0] -is [AssignmentStatementAst] -and 
                    $args[0].Left.VariablePath.UserPath -match 'PSModuleAutoLoadingPreference|EnableScriptBlockLogging'
                }, $true)
                
                foreach ($bypass in $scriptBlockBypass) {
                    $violations += [SecurityViolation]::new(
                        "ETWEvasion",
                        "PowerShell logging bypass detected: $($bypass.Left.VariablePath.UserPath)",
                        [SecuritySeverity]::Critical,
                        $bypass.Extent.StartLineNumber,
                        $bypass.Extent.Text
                    )
                }
                
                # Pattern 2: ETW provider manipulation
                $etwManipulation = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'Set-EtwTraceProvider' -or
                     $args[0].GetCommandName() -eq 'Remove-EtwTraceSession' -or
                     $args[0].GetCommandName() -eq 'Stop-EtwTraceSession')
                }, $true)
                
                foreach ($etw in $etwManipulation) {
                    $violations += [SecurityViolation]::new(
                        "ETWEvasion",
                        "ETW provider manipulation detected: $($etw.GetCommandName())",
                        [SecuritySeverity]::Critical,
                        $etw.Extent.StartLineNumber,
                        $etw.Extent.Text
                    )
                }
                
                # Pattern 3: Registry modifications to disable logging
                $registryLogging = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -match 'Set-ItemProperty|New-ItemProperty' -and
                    $args[0].Extent.Text -match 'HKLM.*Policies.*PowerShell'
                }, $true)
                
                foreach ($reg in $registryLogging) {
                    if ($reg.Extent.Text -match 'EnableScriptBlockLogging|EnableModuleLogging') {
                        $violations += [SecurityViolation]::new(
                            "ETWEvasion",
                            "Registry modification to disable PowerShell logging",
                            [SecuritySeverity]::Critical,
                            $reg.Extent.StartLineNumber,
                            $reg.Extent.Text
                        )
                    }
                }
                
                # Pattern 4: Group Policy modifications
                $groupPolicyBypass = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst] -and 
                    $args[0].Value -match 'PowerShellExecutionPolicy|ScriptBlockLogging|ModuleLogging'
                }, $true)
                
                foreach ($gp in $groupPolicyBypass) {
                    $parent = $gp.Parent
                    while ($parent -and -not ($parent -is [CommandAst])) {
                        $parent = $parent.Parent
                    }
                    if ($parent -and $parent.GetCommandName() -match 'Set-ItemProperty|Remove-ItemProperty') {
                        $violations += [SecurityViolation]::new(
                            "ETWEvasion",
                            "Group Policy modification to bypass security logging",
                            [SecuritySeverity]::Critical,
                            $gp.Extent.StartLineNumber,
                            $gp.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 33: Enhanced PowerShell 2.0 Detection
        $this.SecurityRules.Add([SecurityRule]::new(
            "EnhancedPowerShell2Detection",
            "Detects PowerShell 2.0 usage and related security bypass techniques",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: Direct PowerShell 2.0 invocation (enhanced from existing rule)
                $powershellV2 = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'powershell' -or $args[0].GetCommandName() -eq 'powershell.exe')
                }, $true)
                
                foreach ($ps in $powershellV2) {
                    # Check for -version 2 parameter
                    for ($i = 0; $i -lt $ps.CommandElements.Count; $i++) {
                        $element = $ps.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and $element.ParameterName -match '^v(ersion)?$') {
                            if ($i + 1 -lt $ps.CommandElements.Count) {
                                $nextElement = $ps.CommandElements[$i + 1]
                                if ($nextElement -is [StringConstantExpressionAst] -and $nextElement.Value -eq '2') {
                                    $violations += [SecurityViolation]::new(
                                        "EnhancedPowerShell2Detection",
                                        "PowerShell 2.0 execution detected - bypasses modern security features",
                                        [SecuritySeverity]::High,
                                        $ps.Extent.StartLineNumber,
                                        $ps.Extent.Text
                                    )
                                }
                            }
                        }
                    }
                }
                
                # Pattern 1B: String-based PowerShell 2.0 detection (for external command calls)
                $powershellStrings = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst] -and 
                    $args[0].Value -match 'powershell(\.exe)?\s+.*-v(ersion)?\s+2'
                }, $true)
                
                foreach ($ps in $powershellStrings) {
                    $violations += [SecurityViolation]::new(
                        "EnhancedPowerShell2Detection",
                        "PowerShell 2.0 invocation string detected - bypasses modern security features",
                        [SecuritySeverity]::High,
                        $ps.Extent.StartLineNumber,
                        $ps.Extent.Text
                    )
                }
                
                # Pattern 2: PowerShell ISE usage (often indicates PS 2.0 environment)
                $iseUsage = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'powershell_ise' -or 
                     $args[0].GetCommandName() -eq 'powershell_ise.exe')
                }, $true)
                
                foreach ($ise in $iseUsage) {
                    $violations += [SecurityViolation]::new(
                        "EnhancedPowerShell2Detection",
                        "PowerShell ISE usage detected - may indicate PowerShell 2.0 environment",
                        [SecuritySeverity]::High,
                        $ise.Extent.StartLineNumber,
                        $ise.Extent.Text
                    )
                }
                
                # Pattern 3: .NET Framework 2.0 specific calls
                $dotNet2Calls = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst] -and 
                    ($args[0].Value -match '(?i)v2\.0\.50727|mscorlib[, ].*Version\s*=\s*2\.0\.0\.0|\.NET.*\b2(\.0)?\b|System\.Management\.Automation.*2\.0')
                }, $true)
                
                foreach ($net2 in $dotNet2Calls) {
                    $value = $net2.Value
                
                    $indicator = switch -Regex ($value) {
                        '(?i)v2\.0\.50727' {
                            "CLR v2 runtime version 'v2.0.50727' detected"
                            break
                        }
                        '(?i)mscorlib[, ].*Version\s*=\s*2\.0\.0\.0' {
                            "mscorlib Version=2.0.0.0 reference detected"
                            break
                        }
                        '(?i)\.NET.*\b2(\.0)?\b' {
                            ".NET 2.x reference detected"
                            break
                        }
                        '(?i)System\.Management\.Automation.*2\.0' {
                            "System.Management.Automation v2 reference detected"
                            break
                        }
                        default {
                            "Possible .NET/PowerShell v2 indicator detected: '$($value.Trim())'"
                        }
                    }
                
                    $violations += [SecurityViolation]::new(
                        "EnhancedPowerShell2Detection",
                        "$indicator — may indicate PowerShell v2 or .NET 2.0 usage; review for legacy compatibility and security implications.",
                        [SecuritySeverity]::High,
                        $net2.Extent.StartLineNumber,
                        $net2.Extent.Text
                    )
                }
                
                # Pattern 4: WMI-based PowerShell execution (common PS 2.0 technique)
                $wmiExecution = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'Invoke-WmiMethod' -or 
                     $args[0].GetCommandName() -eq 'Get-WmiObject')
                }, $true)
                
                foreach ($wmi in $wmiExecution) {
                    if ($wmi.Extent.Text -match 'Win32_Process.*powershell|CommandLine.*powershell') {
                        $violations += [SecurityViolation]::new(
                            "EnhancedPowerShell2Detection",
                            "WMI-based PowerShell execution detected - often used for PS 2.0 bypass",
                            [SecuritySeverity]::High,
                            $wmi.Extent.StartLineNumber,
                            $wmi.Extent.Text
                        )
                    }
                }
                
                # Pattern 5: Legacy cmdlet usage specific to PS 2.0
                $legacyCmdlets = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -match '^(ConvertTo-SecureString.*-AsPlainText|New-Object.*System\.Net\.WebClient|Add-PSSnapin)$'
                }, $true)
                
                foreach ($legacy in $legacyCmdlets) {
                    $violations += [SecurityViolation]::new(
                        "EnhancedPowerShell2Detection",
                        "Legacy cmdlet usage detected: $($legacy.GetCommandName()) - common in PowerShell 2.0 environments",
                        [SecuritySeverity]::Medium,
                        $legacy.Extent.StartLineNumber,
                        $legacy.Extent.Text
                    )
                }
                
                return $violations
            }
        ))

        # Phase 1.5C-B: Azure & Cloud Security Rules

        # Rule 34: Azure PowerShell Credential Leaks
        $this.SecurityRules.Add([SecurityRule]::new(
            "AzurePowerShellCredentialLeaks",
            "Detects Azure PowerShell credential exposure and unsafe authentication patterns",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: Connect-AzAccount with plaintext passwords
                $azConnectCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Connect-AzAccount'
                }, $true)
                
                foreach ($call in $azConnectCalls) {
                    # Check for -Credential parameter with plaintext password construction
                    $credentialFound = $false
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and $element.ParameterName -eq 'Credential') {
                            $credentialFound = $true
                            break
                        }
                    }
                    
                    if ($credentialFound) {
                        $violations += [SecurityViolation]::new(
                            "AzurePowerShellCredentialLeaks",
                            "Connect-AzAccount with credential parameter detected. Use Managed Identity or certificate-based auth instead.",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 2: Azure Storage Account keys in variables
                $storageKeys = $Ast.FindAll({
                    $args[0] -is [AssignmentStatementAst] -and 
                    $args[0].Left.VariablePath.UserPath -match 'StorageAccountKey|AccountKey' -and
                    $args[0].Right -is [StringConstantExpressionAst] -and
                    $args[0].Right.Value -match '^[A-Za-z0-9+/]{88}==$'
                }, $true)
                
                foreach ($key in $storageKeys) {
                    $violations += [SecurityViolation]::new(
                        "AzurePowerShellCredentialLeaks",
                        "Azure Storage Account key hardcoded in variable: $($key.Left.VariablePath.UserPath)",
                        [SecuritySeverity]::Critical,
                        $key.Extent.StartLineNumber,
                        $key.Extent.Text
                    )
                }
                
                # Pattern 3: Azure connection strings with embedded credentials
                $connectionStrings = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst] -and 
                    ($args[0].Value -match 'AccountKey=.*' -or
                     $args[0].Value -match 'Password=.*' -or
                     $args[0].Value -match 'User ID=.*Password=')
                }, $true)
                
                foreach ($connStr in $connectionStrings) {
                    if ($connStr.Value -match 'DefaultEndpointsProtocol|database\.windows\.net') {
                        $violations += [SecurityViolation]::new(
                            "AzurePowerShellCredentialLeaks",
                            "Azure connection string with embedded credentials detected",
                            [SecuritySeverity]::Critical,
                            $connStr.Extent.StartLineNumber,
                            $connStr.Extent.Text
                        )
                    }
                }
                
                # Pattern 4: Service Principal secrets in variables
                $spSecrets = $Ast.FindAll({
                    $args[0] -is [AssignmentStatementAst] -and 
                    ($args[0].Left.VariablePath.UserPath -match 'ServicePrincipalKey|AppSecret|ClientSecret' -or
                     $args[0].Left.VariablePath.UserPath -match 'servicePrincipalKey|appSecret|clientSecret') -and
                    $args[0].Right -is [StringConstantExpressionAst]
                }, $true)
                
                foreach ($secret in $spSecrets) {
                    $violations += [SecurityViolation]::new(
                        "AzurePowerShellCredentialLeaks",
                        "Azure Service Principal secret hardcoded in variable: $($secret.Left.VariablePath.UserPath)",
                        [SecuritySeverity]::Critical,
                        $secret.Extent.StartLineNumber,
                        $secret.Extent.Text
                    )
                }
                
                # Pattern 5: Azure DevOps Personal Access Tokens
                $patTokens = $Ast.FindAll({
                    $args[0] -is [AssignmentStatementAst] -and 
                    ($args[0].Left.VariablePath.UserPath -match 'DevOpsToken|PAT|PersonalAccessToken' -or
                     $args[0].Left.VariablePath.UserPath -match 'devOpsToken|pat|personalAccessToken') -and
                    $args[0].Right -is [StringConstantExpressionAst] -and
                    $args[0].Right.Value -match '^[a-z0-9]{52}$'
                }, $true)
                
                foreach ($pat in $patTokens) {
                    $violations += [SecurityViolation]::new(
                        "AzurePowerShellCredentialLeaks",
                        "Azure DevOps Personal Access Token hardcoded: $($pat.Left.VariablePath.UserPath)",
                        [SecuritySeverity]::Critical,
                        $pat.Extent.StartLineNumber,
                        $pat.Extent.Text
                    )
                }
                
                # Pattern 6: Azure Function keys in URLs or variables
                $functionKeys = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst] -and 
                    ($args[0].Value -match '[\?&]code=[A-Za-z0-9+/=]{20,}' -or
                     $args[0].Value -match 'FunctionKeyValue.*=')
                }, $true)
                
                foreach ($funcKey in $functionKeys) {
                    if ($funcKey.Value -match 'azurewebsites\.net|functions\.azure\.com') {
                        $violations += [SecurityViolation]::new(
                            "AzurePowerShellCredentialLeaks",
                            "Azure Function key hardcoded in URL or variable",
                            [SecuritySeverity]::High,
                            $funcKey.Extent.StartLineNumber,
                            $funcKey.Extent.Text
                        )
                    }
                }
                
                # Pattern 7: Unsafe Azure Key Vault access (without proper authentication)
                $kvCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -match 'Get-AzKeyVaultSecret|Set-AzKeyVaultSecret'
                }, $true)
                
                foreach ($kv in $kvCalls) {
                    # Check if used in a context where credentials are being retrieved unsafely
                    $parent = $kv.Parent
                    while ($parent -and -not ($parent -is [AssignmentStatementAst])) {
                        $parent = $parent.Parent
                    }
                    
                    if ($parent -and $parent -is [AssignmentStatementAst] -and 
                        $parent.Left.VariablePath.UserPath -match 'password|secret|key|credential') {
                        $violations += [SecurityViolation]::new(
                            "AzurePowerShellCredentialLeaks",
                            "Azure Key Vault secret retrieved into variable. Ensure proper access controls and avoid plaintext handling.",
                            [SecuritySeverity]::Medium,
                            $kv.Extent.StartLineNumber,
                            $kv.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 35: Azure Resource Exposure
        $this.SecurityRules.Add([SecurityRule]::new(
            "AzureResourceExposure",
            "Detects unsafe Azure resource configurations that may expose data or services",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: Public blob containers
                $blobCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'Set-AzStorageContainerAcl' -or
                     $args[0].GetCommandName() -eq 'New-AzStorageContainer')
                }, $true)
                
                foreach ($call in $blobCalls) {
                    # Check for public access levels
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and $element.ParameterName -eq 'Permission') {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement -is [StringConstantExpressionAst] -and 
                                $nextElement.Value -match 'Blob|Container') {
                                $violations += [SecurityViolation]::new(
                                    "AzureResourceExposure",
                                    "Azure Storage Container set to public access: $($nextElement.Value)",
                                    [SecuritySeverity]::High,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                # Pattern 2: SQL Server firewall rules allowing all IPs
                $sqlFirewallCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'New-AzSqlServerFirewallRule'
                }, $true)
                
                foreach ($call in $sqlFirewallCalls) {
                    $hasOpenRule = $false
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            ($element.ParameterName -eq 'StartIpAddress' -or $element.ParameterName -eq 'EndIpAddress')) {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement -is [StringConstantExpressionAst] -and 
                                $nextElement.Value -match '^0\.0\.0\.0$') {
                                $hasOpenRule = $true
                            }
                        }
                    }
                    
                    if ($hasOpenRule) {
                        $violations += [SecurityViolation]::new(
                            "AzureResourceExposure",
                            "Azure SQL firewall rule allows access from all IPs (0.0.0.0)",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 3: Network Security Group rules allowing broad access
                $nsgCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Add-AzNetworkSecurityRuleConfig'
                }, $true)
                
                foreach ($call in $nsgCalls) {
                    $hasBroadSource = $false
                    $hasInbound = $false
                    
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst]) {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($element.ParameterName -eq 'SourceAddressPrefix' -and
                                $nextElement -is [StringConstantExpressionAst] -and
                                $nextElement.Value -match '^\*$|^0\.0\.0\.0/0$|^Internet$') {
                                $hasBroadSource = $true
                            }
                            if ($element.ParameterName -eq 'Direction' -and
                                $nextElement -is [StringConstantExpressionAst] -and
                                $nextElement.Value -eq 'Inbound') {
                                $hasInbound = $true
                            }
                        }
                    }
                    
                    if ($hasBroadSource -and $hasInbound) {
                        $violations += [SecurityViolation]::new(
                            "AzureResourceExposure",
                            "NSG rule allows inbound traffic from any source (*)",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 4: Public IP assignments without justification
                $publicIpCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'New-AzPublicIpAddress'
                }, $true)
                
                foreach ($call in $publicIpCalls) {
                    # Check if it's for a production resource (basic heuristic)
                    $callText = $call.Extent.Text.ToLower()
                    if ($callText -match 'prod|production|public') {
                        $violations += [SecurityViolation]::new(
                            "AzureResourceExposure",
                            "Public IP address creation detected. Ensure this is necessary and properly secured.",
                            [SecuritySeverity]::Medium,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 5: Key Vault with overly permissive access policies
                $kvPolicyCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzKeyVaultAccessPolicy'
                }, $true)
                
                foreach ($call in $kvPolicyCalls) {
                    $hasAllPermissions = $false
                    
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            ($element.ParameterName -eq 'PermissionsToSecrets' -or 
                             $element.ParameterName -eq 'PermissionsToKeys')) {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement -is [ArrayExpressionAst] -or
                                ($nextElement -is [StringConstantExpressionAst] -and 
                                 $nextElement.Value -match 'all|\*')) {
                                $hasAllPermissions = $true
                            }
                        }
                    }
                    
                    if ($hasAllPermissions) {
                        $violations += [SecurityViolation]::new(
                            "AzureResourceExposure",
                            "Key Vault access policy grants excessive permissions",
                            [SecuritySeverity]::Medium,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 36: Azure Entra ID Privileged Operations
        $this.SecurityRules.Add([SecurityRule]::new(
            "AzureEntraIDPrivilegedOperations",
            "Detects dangerous Azure Entra ID (Azure AD) privileged operations",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: Add-AzureADDirectoryRoleMember with Global Admin/Privileged roles
                $addRoleCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'Add-AzureADDirectoryRoleMember' -or
                     $args[0].GetCommandName() -eq 'Add-MgDirectoryRoleMember')
                }, $true)
                
                foreach ($call in $addRoleCalls) {
                    $callText = $call.Extent.Text.ToLower()
                    if ($callText -match 'global.*admin|company.*admin|privileged.*role|user.*admin|security.*admin') {
                        $violations += [SecurityViolation]::new(
                            "AzureEntraIDPrivilegedOperations",
                            "Adding member to privileged Azure AD role detected. Requires approval and justification.",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 2: Set-AzureADUser with privileged account modifications
                $setUserCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'Set-AzureADUser' -or
                     $args[0].GetCommandName() -eq 'Update-MgUser')
                }, $true)
                
                foreach ($call in $setUserCalls) {
                    $callText = $call.Extent.Text.ToLower()
                    if ($callText -match 'admin|privileged|global|security') {
                        $violations += [SecurityViolation]::new(
                            "AzureEntraIDPrivilegedOperations",
                            "Modifying privileged user account detected. Ensure proper authorization.",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 3: New-AzureADApplication with excessive permissions
                $newAppCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'New-AzureADApplication' -or
                     $args[0].GetCommandName() -eq 'New-MgApplication')
                }, $true)
                
                foreach ($call in $newAppCalls) {
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            ($element.ParameterName -eq 'RequiredResourceAccess' -or
                             $element.ParameterName -eq 'AppRoles')) {
                            $violations += [SecurityViolation]::new(
                                "AzureEntraIDPrivilegedOperations",
                                "Creating Azure AD application with resource access permissions. Review for excessive permissions.",
                                [SecuritySeverity]::High,
                                $call.Extent.StartLineNumber,
                                $call.Extent.Text
                            )
                            break
                        }
                    }
                }
                
                # Pattern 4: Remove-AzureADUser bulk operations without confirmation
                $removeUserCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'Remove-AzureADUser' -or
                     $args[0].GetCommandName() -eq 'Remove-MgUser')
                }, $true)
                
                foreach ($call in $removeUserCalls) {
                    # Check if it's in a loop or has wildcard/array
                    $parent = $call.Parent
                    $isInLoop = $false
                    while ($parent) {
                        if ($parent -is [LoopStatementAst] -or $parent -is [ForEachStatementAst]) {
                            $isInLoop = $true
                            break
                        }
                        $parent = $parent.Parent
                    }
                    
                    if ($isInLoop) {
                        $violations += [SecurityViolation]::new(
                            "AzureEntraIDPrivilegedOperations",
                            "Bulk user deletion detected. Ensure proper confirmation and backup procedures.",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 5: Set-AzureADPolicy bypassing security policies
                $setPolicyCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzureADPolicy'
                }, $true)
                
                foreach ($call in $setPolicyCalls) {
                    $violations += [SecurityViolation]::new(
                        "AzureEntraIDPrivilegedOperations",
                        "Modifying Azure AD policy detected. Ensure compliance with security standards.",
                        [SecuritySeverity]::High,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                return $violations
            }
        ))

        # Rule 37: Azure Data Exfiltration
        $this.SecurityRules.Add([SecurityRule]::new(
            "AzureDataExfiltration",
            "Detects potential data exfiltration attempts from Azure services",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: Start-AzStorageBlobCopy to external accounts
                $blobCopyCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'Start-AzStorageBlobCopy' -or
                     $args[0].GetCommandName() -eq 'Start-AzureStorageBlobCopy')
                }, $true)
                
                foreach ($call in $blobCopyCalls) {
                    # Check for external destination
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            ($element.ParameterName -eq 'DestinationUri' -or
                             $element.ParameterName -eq 'AbsoluteUri')) {
                            $violations += [SecurityViolation]::new(
                                "AzureDataExfiltration",
                                "Blob copy to external URI detected. Verify destination is authorized.",
                                [SecuritySeverity]::Critical,
                                $call.Extent.StartLineNumber,
                                $call.Extent.Text
                            )
                            break
                        }
                    }
                }
                
                # Pattern 2: Export-AzSqlDatabase to public storage
                $exportDbCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Export-AzSqlDatabase'
                }, $true)
                
                foreach ($call in $exportDbCalls) {
                    $violations += [SecurityViolation]::new(
                        "AzureDataExfiltration",
                        "SQL Database export detected. Ensure destination storage is secured and authorized.",
                        [SecuritySeverity]::Critical,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                # Pattern 3: Get-AzKeyVaultSecret with bulk retrieval
                $getSecretCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'Get-AzKeyVaultSecret' -or
                     $args[0].GetCommandName() -eq 'Get-AzureKeyVaultSecret')
                }, $true)
                
                foreach ($call in $getSecretCalls) {
                    # Check if it's in a loop (bulk retrieval)
                    $parent = $call.Parent
                    $isInLoop = $false
                    while ($parent) {
                        if ($parent -is [LoopStatementAst] -or $parent -is [ForEachStatementAst]) {
                            $isInLoop = $true
                            break
                        }
                        $parent = $parent.Parent
                    }
                    
                    if ($isInLoop) {
                        $violations += [SecurityViolation]::new(
                            "AzureDataExfiltration",
                            "Bulk Key Vault secret retrieval detected. Ensure proper authorization and monitoring.",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 4: Export-AzResourceGroup with sensitive resources
                $exportRgCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Export-AzResourceGroup'
                }, $true)
                
                foreach ($call in $exportRgCalls) {
                    $violations += [SecurityViolation]::new(
                        "AzureDataExfiltration",
                        "Resource group export detected. May contain sensitive configuration data.",
                        [SecuritySeverity]::High,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                # Pattern 5: Backup-AzKeyVault to uncontrolled locations
                $backupKvCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Backup-AzKeyVault'
                }, $true)
                
                foreach ($call in $backupKvCalls) {
                    $violations += [SecurityViolation]::new(
                        "AzureDataExfiltration",
                        "Key Vault backup detected. Ensure backup location is secure and properly monitored.",
                        [SecuritySeverity]::High,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                return $violations
            }
        ))

        # Rule 38: Azure Logging Disabled
        $this.SecurityRules.Add([SecurityRule]::new(
            "AzureLoggingDisabled",
            "Detects attempts to disable Azure logging and monitoring",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: Set-AzDiagnosticSetting with disabled categories
                $diagCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzDiagnosticSetting'
                }, $true)
                
                foreach ($call in $diagCalls) {
                    $callText = $call.Extent.Text.ToLower()
                    if ($callText -match '\$false|-enabled:\$false|enabled\s*=\s*\$false') {
                        $violations += [SecurityViolation]::new(
                            "AzureLoggingDisabled",
                            "Azure diagnostic setting being disabled. Logging should always be enabled for compliance.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 2: Remove-AzLogProfile
                $removeLogCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Remove-AzLogProfile'
                }, $true)
                
                foreach ($call in $removeLogCalls) {
                    $violations += [SecurityViolation]::new(
                        "AzureLoggingDisabled",
                        "Removing Azure log profile. This disables activity log collection.",
                        [SecuritySeverity]::Critical,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                # Pattern 3: Set-AzSecurityContact with disabled notifications
                $secContactCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzSecurityContact'
                }, $true)
                
                foreach ($call in $secContactCalls) {
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            ($element.ParameterName -eq 'AlertsToAdmins' -or
                             $element.ParameterName -eq 'AlertNotifications')) {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement.Extent.Text -match '\$false|Off') {
                                $violations += [SecurityViolation]::new(
                                    "AzureLoggingDisabled",
                                    "Security contact notifications being disabled. Keep enabled for security alerts.",
                                    [SecuritySeverity]::High,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                # Pattern 4: Disable-AzActivityLogAlert
                $disableAlertCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Disable-AzActivityLogAlert'
                }, $true)
                
                foreach ($call in $disableAlertCalls) {
                    $violations += [SecurityViolation]::new(
                        "AzureLoggingDisabled",
                        "Disabling activity log alert. Maintain alerts for security monitoring.",
                        [SecuritySeverity]::High,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                # Pattern 5: Set-AzMonitorLogProfile with insufficient retention
                $logProfileCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzMonitorLogProfile'
                }, $true)
                
                foreach ($call in $logProfileCalls) {
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'RetentionInDays') {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement -is [ConstantExpressionAst]) {
                                $days = [int]$nextElement.Value
                                if ($days -lt 90) {
                                    $violations += [SecurityViolation]::new(
                                        "AzureLoggingDisabled",
                                        "Log retention set to less than 90 days ($days). Increase for compliance requirements.",
                                        [SecuritySeverity]::Medium,
                                        $call.Extent.StartLineNumber,
                                        $call.Extent.Text
                                    )
                                }
                            }
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 39: Azure Subscription Management
        $this.SecurityRules.Add([SecurityRule]::new(
            "AzureSubscriptionManagement",
            "Detects unsafe Azure subscription management operations",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: Set-AzContext with production subscription switching
                $setContextCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzContext'
                }, $true)
                
                foreach ($call in $setContextCalls) {
                    $callText = $call.Extent.Text.ToLower()
                    if ($callText -match 'prod|production') {
                        $violations += [SecurityViolation]::new(
                            "AzureSubscriptionManagement",
                            "Switching to production subscription detected. Ensure proper authorization.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 2: New-AzRoleDefinition with overly broad permissions
                $newRoleCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'New-AzRoleDefinition'
                }, $true)
                
                foreach ($call in $newRoleCalls) {
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'Actions') {
                            $nextElement = $call.CommandElements[$i + 1]
                            $actionsText = $nextElement.Extent.Text
                            if ($actionsText -match '\*|Microsoft\.\*/') {
                                $violations += [SecurityViolation]::new(
                                    "AzureSubscriptionManagement",
                                    "Creating role definition with wildcard permissions (*). Use least privilege principle.",
                                    [SecuritySeverity]::Critical,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                # Pattern 3: Remove-AzRoleAssignment bulk operations
                $removeRoleCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Remove-AzRoleAssignment'
                }, $true)
                
                foreach ($call in $removeRoleCalls) {
                    # Check if it's in a loop
                    $parent = $call.Parent
                    $isInLoop = $false
                    while ($parent) {
                        if ($parent -is [LoopStatementAst] -or $parent -is [ForEachStatementAst]) {
                            $isInLoop = $true
                            break
                        }
                        $parent = $parent.Parent
                    }
                    
                    if ($isInLoop) {
                        $violations += [SecurityViolation]::new(
                            "AzureSubscriptionManagement",
                            "Bulk role assignment removal detected. Verify authorization and backup.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 4: Set-AzSubscription policy modifications
                $setSubCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzSubscription'
                }, $true)
                
                foreach ($call in $setSubCalls) {
                    $violations += [SecurityViolation]::new(
                        "AzureSubscriptionManagement",
                        "Modifying subscription settings detected. Ensure change management approval.",
                        [SecuritySeverity]::High,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                # Pattern 5: Move-AzResource cross-subscription without validation
                $moveResourceCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Move-AzResource'
                }, $true)
                
                foreach ($call in $moveResourceCalls) {
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'DestinationSubscriptionId') {
                            $violations += [SecurityViolation]::new(
                                "AzureSubscriptionManagement",
                                "Cross-subscription resource move detected. Verify security implications.",
                                [SecuritySeverity]::High,
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

        # Rule 40: Azure Compute Security Violations
        $this.SecurityRules.Add([SecurityRule]::new(
            "AzureComputeSecurityViolations",
            "Detects insecure Azure VM and container configurations",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: New-AzVm with public IP and RDP/SSH open
                $newVmCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'New-AzVm' -or
                     $args[0].GetCommandName() -eq 'New-AzVM')
                }, $true)
                
                foreach ($call in $newVmCalls) {
                    $hasPublicIp = $false
                    $hasOpenRdpSsh = $false
                    
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst]) {
                            if ($element.ParameterName -eq 'PublicIpAddressName' -or
                                $element.ParameterName -eq 'PublicIpAddress') {
                                $hasPublicIp = $true
                            }
                            if ($element.ParameterName -eq 'OpenPorts') {
                                $nextElement = $call.CommandElements[$i + 1]
                                $portsText = $nextElement.Extent.Text
                                if ($portsText -match '22|3389|rdp|ssh') {
                                    $hasOpenRdpSsh = $true
                                }
                            }
                        }
                    }
                    
                    if ($hasPublicIp -and $hasOpenRdpSsh) {
                        $violations += [SecurityViolation]::new(
                            "AzureComputeSecurityViolations",
                            "VM with public IP and open RDP/SSH ports detected. Use Azure Bastion or VPN instead.",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 2: Set-AzVMExtension with custom script execution
                $vmExtCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzVMExtension'
                }, $true)
                
                foreach ($call in $vmExtCalls) {
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'ExtensionType') {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement.Extent.Text -match 'CustomScript') {
                                $violations += [SecurityViolation]::new(
                                    "AzureComputeSecurityViolations",
                                    "Custom script VM extension detected. Ensure script source is trusted and validated.",
                                    [SecuritySeverity]::High,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                # Pattern 3: Add-AzVMDataDisk without encryption
                $addDiskCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Add-AzVMDataDisk'
                }, $true)
                
                foreach ($call in $addDiskCalls) {
                    $hasEncryption = $false
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            ($element.ParameterName -eq 'DiskEncryptionSetId' -or
                             $element.ParameterName -eq 'Encryption')) {
                            $hasEncryption = $true
                            break
                        }
                    }
                    
                    if (-not $hasEncryption) {
                        $violations += [SecurityViolation]::new(
                            "AzureComputeSecurityViolations",
                            "Adding VM data disk without encryption. Enable Azure Disk Encryption.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 4: Set-AzVMOperatingSystem with disabled security features
                $setOsCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzVMOperatingSystem'
                }, $true)
                
                foreach ($call in $setOsCalls) {
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'DisablePasswordAuthentication') {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement.Extent.Text -match '\$false') {
                                $violations += [SecurityViolation]::new(
                                    "AzureComputeSecurityViolations",
                                    "Password authentication enabled on Linux VM. Use SSH keys only.",
                                    [SecuritySeverity]::High,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                # Pattern 5: New-AzContainerGroup with privileged containers
                $containerCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'New-AzContainerGroup'
                }, $true)
                
                foreach ($call in $containerCalls) {
                    $callText = $call.Extent.Text.ToLower()
                    if ($callText -match 'privileged|--privileged') {
                        $violations += [SecurityViolation]::new(
                            "AzureComputeSecurityViolations",
                            "Creating privileged container detected. Avoid privileged mode for security.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 41: Azure DevOps Security Issues
        $this.SecurityRules.Add([SecurityRule]::new(
            "AzureDevOpsSecurityIssues",
            "Detects security issues in Azure DevOps configurations",
            [SecuritySeverity]::Medium,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: Set-AzDevOpsVariable with secrets in plaintext
                $setVarCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzDevOpsVariable'
                }, $true)
                
                foreach ($call in $setVarCalls) {
                    $hasSecret = $false
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'IsSecret') {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement.Extent.Text -match '\$false') {
                                $hasSecret = $true
                            }
                        }
                    }
                    
                    $callText = $call.Extent.Text.ToLower()
                    if (($callText -match 'password|secret|key|token|credential') -and -not $hasSecret) {
                        $violations += [SecurityViolation]::new(
                            "AzureDevOpsSecurityIssues",
                            "Azure DevOps variable containing sensitive data not marked as secret.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 2: New-AzDevOpsPipeline with elevated permissions
                $newPipelineCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'New-AzDevOpsPipeline'
                }, $true)
                
                foreach ($call in $newPipelineCalls) {
                    $callText = $call.Extent.Text.ToLower()
                    if ($callText -match 'admin|elevated|privileged') {
                        $violations += [SecurityViolation]::new(
                            "AzureDevOpsSecurityIssues",
                            "Pipeline with elevated permissions detected. Use least privilege principle.",
                            [SecuritySeverity]::Medium,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 3: Add-AzDevOpsServiceConnection with broad access
                $svcConnCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Add-AzDevOpsServiceConnection'
                }, $true)
                
                foreach ($call in $svcConnCalls) {
                    $violations += [SecurityViolation]::new(
                        "AzureDevOpsSecurityIssues",
                        "Service connection creation detected. Ensure proper scope and access controls.",
                        [SecuritySeverity]::Medium,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                # Pattern 4: Set-AzDevOpsRepositoryPolicy disabling security checks
                $setPolicyCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzDevOpsRepositoryPolicy'
                }, $true)
                
                foreach ($call in $setPolicyCalls) {
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'Enabled') {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement.Extent.Text -match '\$false') {
                                $violations += [SecurityViolation]::new(
                                    "AzureDevOpsSecurityIssues",
                                    "Repository policy being disabled. Maintain security checks for code quality.",
                                    [SecuritySeverity]::High,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                # Pattern 5: Grant-AzDevOpsPermission with excessive scope
                $grantPermCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Grant-AzDevOpsPermission'
                }, $true)
                
                foreach ($call in $grantPermCalls) {
                    $callText = $call.Extent.Text.ToLower()
                    if ($callText -match 'allow.*all|administrator|full.*control') {
                        $violations += [SecurityViolation]::new(
                            "AzureDevOpsSecurityIssues",
                            "Granting excessive Azure DevOps permissions. Apply least privilege principle.",
                            [SecuritySeverity]::Medium,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 42: Azure Encryption Bypass
        $this.SecurityRules.Add([SecurityRule]::new(
            "AzureEncryptionBypass",
            "Detects attempts to disable encryption on Azure resources",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: Set-AzStorageAccount with encryption disabled
                $storageAcctCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzStorageAccount'
                }, $true)
                
                foreach ($call in $storageAcctCalls) {
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            ($element.ParameterName -eq 'EnableEncryptionService' -or
                             $element.ParameterName -eq 'RequireInfrastructureEncryption')) {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement.Extent.Text -match '\$false|None') {
                                $violations += [SecurityViolation]::new(
                                    "AzureEncryptionBypass",
                                    "Storage account encryption being disabled. Encryption is required for data protection.",
                                    [SecuritySeverity]::Critical,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                # Pattern 2: New-AzDisk without encryption
                $newDiskCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'New-AzDisk'
                }, $true)
                
                foreach ($call in $newDiskCalls) {
                    $hasEncryption = $false
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            ($element.ParameterName -eq 'DiskEncryptionSetId' -or
                             $element.ParameterName -eq 'EncryptionType')) {
                            $hasEncryption = $true
                            break
                        }
                    }
                    
                    if (-not $hasEncryption) {
                        $violations += [SecurityViolation]::new(
                            "AzureEncryptionBypass",
                            "Creating disk without encryption. Enable encryption at rest.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 3: Set-AzSqlDatabase with TDE disabled
                $sqlDbCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'Set-AzSqlDatabase' -or
                     $args[0].GetCommandName() -eq 'Set-AzSqlDatabaseTransparentDataEncryption')
                }, $true)
                
                foreach ($call in $sqlDbCalls) {
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'State') {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement.Extent.Text -match 'Disabled') {
                                $violations += [SecurityViolation]::new(
                                    "AzureEncryptionBypass",
                                    "SQL Database Transparent Data Encryption (TDE) being disabled. Keep enabled for compliance.",
                                    [SecuritySeverity]::Critical,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                # Pattern 4: New-AzVirtualMachine without disk encryption
                $newVmCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'New-AzVirtualMachine'
                }, $true)
                
                foreach ($call in $newVmCalls) {
                    $hasEncryption = $false
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -match 'Encryption') {
                            $hasEncryption = $true
                            break
                        }
                    }
                    
                    if (-not $hasEncryption) {
                        $violations += [SecurityViolation]::new(
                            "AzureEncryptionBypass",
                            "VM created without disk encryption. Enable Azure Disk Encryption (ADE).",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 5: Set-AzKeyVault without HSM protection in production
                $kvCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -eq 'Set-AzKeyVault' -or
                     $args[0].GetCommandName() -eq 'New-AzKeyVault')
                }, $true)
                
                foreach ($call in $kvCalls) {
                    $callText = $call.Extent.Text.ToLower()
                    $hasHsm = $callText -match 'enablehsmprotection|sku.*premium'
                    $isProd = $callText -match 'prod|production'
                    
                    if ($isProd -and -not $hasHsm) {
                        $violations += [SecurityViolation]::new(
                            "AzureEncryptionBypass",
                            "Production Key Vault without HSM protection. Use Premium SKU with HSM for production.",
                            [SecuritySeverity]::Medium,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 43: Azure Policy and Compliance
        $this.SecurityRules.Add([SecurityRule]::new(
            "AzurePolicyAndCompliance",
            "Detects modifications to Azure policy and compliance settings",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: Remove-AzPolicyAssignment
                $removePolicyCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Remove-AzPolicyAssignment'
                }, $true)
                
                foreach ($call in $removePolicyCalls) {
                    $violations += [SecurityViolation]::new(
                        "AzurePolicyAndCompliance",
                        "Removing Azure policy assignment. Ensure compliance requirements are maintained.",
                        [SecuritySeverity]::High,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                # Pattern 2: Set-AzPolicyDefinition with weakened controls
                $setPolicyDefCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzPolicyDefinition'
                }, $true)
                
                foreach ($call in $setPolicyDefCalls) {
                    $callText = $call.Extent.Text.ToLower()
                    if ($callText -match 'disabled|audit.*only|deny.*false') {
                        $violations += [SecurityViolation]::new(
                            "AzurePolicyAndCompliance",
                            "Modifying policy definition to weaken controls. Review for compliance impact.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 3: New-AzPolicyExemption without justification
                $exemptionCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'New-AzPolicyExemption'
                }, $true)
                
                foreach ($call in $exemptionCalls) {
                    $hasDescription = $false
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'Description') {
                            $hasDescription = $true
                            break
                        }
                    }
                    
                    if (-not $hasDescription) {
                        $violations += [SecurityViolation]::new(
                            "AzurePolicyAndCompliance",
                            "Policy exemption without description/justification. Document reason for exemption.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 4: Disable-AzSecurityContact
                $disableSecCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Disable-AzSecurityContact'
                }, $true)
                
                foreach ($call in $disableSecCalls) {
                    $violations += [SecurityViolation]::new(
                        "AzurePolicyAndCompliance",
                        "Disabling security contact. Maintain active security contacts for incident response.",
                        [SecuritySeverity]::High,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                # Pattern 5: Set-AzSecurityPricing to free tier in production
                $pricingCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Set-AzSecurityPricing'
                }, $true)
                
                foreach ($call in $pricingCalls) {
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'PricingTier') {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement.Extent.Text -match 'Free') {
                                $violations += [SecurityViolation]::new(
                                    "AzurePolicyAndCompliance",
                                    "Setting Security Center to Free tier. Use Standard tier for production environments.",
                                    [SecuritySeverity]::Medium,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 44: JEA Configuration Vulnerabilities
        $this.SecurityRules.Add([SecurityRule]::new(
            "JEAConfigurationVulnerabilities",
            "Detects security vulnerabilities in JEA (Just Enough Administration) configurations",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: Role capability files with wildcard cmdlets
                $roleCapabilityStrings = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst] -and
                    $args[0].Value -match 'VisibleCmdlets.*\*|VisibleFunctions.*\*|VisibleAliases.*\*'
                }, $true)
                
                foreach ($string in $roleCapabilityStrings) {
                    $violations += [SecurityViolation]::new(
                        "JEAConfigurationVulnerabilities",
                        "JEA role capability using wildcards (*) for visible cmdlets/functions. Use explicit cmdlet lists.",
                        [SecuritySeverity]::High,
                        $string.Extent.StartLineNumber,
                        $string.Extent.Text
                    )
                }
                
                # Pattern 2: Session configuration without transcript logging
                $sessionConfigCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Register-PSSessionConfiguration'
                }, $true)
                
                foreach ($call in $sessionConfigCalls) {
                    $hasTranscript = $false
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'TranscriptDirectory') {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement.Extent.Text -notmatch '\$null') {
                                $hasTranscript = $true
                            }
                        }
                    }
                    
                    if (-not $hasTranscript) {
                        $violations += [SecurityViolation]::new(
                            "JEAConfigurationVulnerabilities",
                            "JEA session configuration without transcript logging. Enable TranscriptDirectory for auditing.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 3: RunAsCredential instead of virtual account
                foreach ($call in $sessionConfigCalls) {
                    $hasRunAsCred = $false
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'RunAsCredential') {
                            $hasRunAsCred = $true
                            break
                        }
                    }
                    
                    if ($hasRunAsCred) {
                        $violations += [SecurityViolation]::new(
                            "JEAConfigurationVulnerabilities",
                            "JEA using RunAsCredential instead of RunAsVirtualAccount. Use virtual accounts for better security.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 4: Role capabilities allowing dangerous cmdlets
                $dangerousCmdlets = @('Invoke-Expression', 'Invoke-Command', 'Enter-PSSession', 'Add-Type', 'New-Object')
                foreach ($cmdlet in $dangerousCmdlets) {
                    $dangerousRoles = $Ast.FindAll({
                        $args[0] -is [StringConstantExpressionAst] -and
                        $args[0].Value -match "VisibleCmdlets.*$cmdlet"
                    }, $true)
                    
                    foreach ($role in $dangerousRoles) {
                        $violations += [SecurityViolation]::new(
                            "JEAConfigurationVulnerabilities",
                            "JEA role capability includes dangerous cmdlet: $cmdlet. Remove or restrict carefully.",
                            [SecuritySeverity]::Critical,
                            $role.Extent.StartLineNumber,
                            $role.Extent.Text
                        )
                    }
                }
                
                # Pattern 5: Session configuration with full language mode
                foreach ($call in $sessionConfigCalls) {
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'SessionType') {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement.Extent.Text -match 'Default') {
                                $violations += [SecurityViolation]::new(
                                    "JEAConfigurationVulnerabilities",
                                    "JEA session using Default (full language) mode. Use RestrictedRemoteServer for JEA.",
                                    [SecuritySeverity]::Critical,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                # Pattern 6: Execution policy bypass in JEA
                foreach ($call in $sessionConfigCalls) {
                    for ($i = 0; $i -lt $call.CommandElements.Count - 1; $i++) {
                        $element = $call.CommandElements[$i]
                        if ($element -is [CommandParameterAst] -and 
                            $element.ParameterName -eq 'ExecutionPolicy') {
                            $nextElement = $call.CommandElements[$i + 1]
                            if ($nextElement.Extent.Text -match 'Bypass|Unrestricted') {
                                $violations += [SecurityViolation]::new(
                                    "JEAConfigurationVulnerabilities",
                                    "JEA session with Bypass/Unrestricted execution policy. Use RemoteSigned or AllSigned.",
                                    [SecuritySeverity]::High,
                                    $call.Extent.StartLineNumber,
                                    $call.Extent.Text
                                )
                            }
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Rule 45: DSC Security Issues
        $this.SecurityRules.Add([SecurityRule]::new(
            "DSCSecurityIssues",
            "Detects security issues in DSC (Desired State Configuration) scripts",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: Unsafe Configuration data handling with plaintext credentials
                $configCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Configuration'
                }, $true)
                
                foreach ($call in $configCalls) {
                    # Look for PsDscAllowPlainTextPassword in ConfigurationData
                    $parent = $call.Parent
                    $scriptText = if ($parent) { $parent.Extent.Text } else { $call.Extent.Text }
                    if ($scriptText -match 'PsDscAllowPlainTextPassword\s*=\s*\$true') {
                        $violations += [SecurityViolation]::new(
                            "DSCSecurityIssues",
                            "DSC Configuration allows plaintext passwords (PsDscAllowPlainTextPassword). Use certificates for credential encryption.",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 2: MOF file credential exposure
                $exportCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    ($args[0].GetCommandName() -match 'Export.*MOF|Start-DscConfiguration')
                }, $true)
                
                foreach ($call in $exportCalls) {
                    $callText = $call.Extent.Text.ToLower()
                    if ($callText -match 'password|credential' -and $callText -notmatch 'pscredential') {
                        $violations += [SecurityViolation]::new(
                            "DSCSecurityIssues",
                            "DSC MOF export may contain credentials. Ensure proper encryption is configured.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 3: DSC credential storage issues - ConvertTo-SecureString in DSC
                $dscSecureStringCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'ConvertTo-SecureString'
                }, $true)
                
                foreach ($call in $dscSecureStringCalls) {
                    # Check if we're in a DSC Configuration block
                    $parent = $call.Parent
                    $inDscConfig = $false
                    while ($parent) {
                        if ($parent -is [CommandAst] -and $parent.GetCommandName() -eq 'Configuration') {
                            $inDscConfig = $true
                            break
                        }
                        $parent = $parent.Parent
                    }
                    
                    if ($inDscConfig) {
                        # Check for AsPlainText
                        $hasAsPlainText = $false
                        foreach ($element in $call.CommandElements) {
                            if ($element -is [CommandParameterAst] -and $element.ParameterName -eq 'AsPlainText') {
                                $hasAsPlainText = $true
                                break
                            }
                        }
                        
                        if ($hasAsPlainText) {
                            $violations += [SecurityViolation]::new(
                                "DSCSecurityIssues",
                                "DSC Configuration using ConvertTo-SecureString -AsPlainText. Use certificate-based credential encryption.",
                                [SecuritySeverity]::Critical,
                                $call.Extent.StartLineNumber,
                                $call.Extent.Text
                            )
                        }
                    }
                }
                
                # Pattern 4: DSC without CertificateId for credential encryption
                foreach ($call in $configCalls) {
                    $scriptBlock = $call.Parent
                    if ($scriptBlock) {
                        $blockText = $scriptBlock.Extent.Text
                        $hasCredential = $blockText -match '\[PSCredential\]|\$Credential'
                        $hasCertConfig = $blockText -match 'CertificateId|CertificateFile'
                        
                        if ($hasCredential -and -not $hasCertConfig) {
                            $violations += [SecurityViolation]::new(
                                "DSCSecurityIssues",
                                "DSC Configuration uses credentials without certificate encryption (CertificateId). Configure credential encryption.",
                                [SecuritySeverity]::High,
                                $call.Extent.StartLineNumber,
                                $call.Extent.Text
                            )
                        }
                    }
                }
                
                # Pattern 5: Unsafe DSC resource parameters
                $resourceCalls = $Ast.FindAll({
                    $args[0] -is [DynamicKeywordStatementAst]
                }, $true)
                
                foreach ($call in $resourceCalls) {
                    $callText = $call.Extent.Text.ToLower()
                    if ($callText -match 'script\s*{' -or $callText -match 'getscript\s*=\s*{.*invoke-expression') {
                        $violations += [SecurityViolation]::new(
                            "DSCSecurityIssues",
                            "DSC Script resource with potentially unsafe script blocks. Review for injection risks.",
                            [SecuritySeverity]::Medium,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Rule 46: Deprecated Cmdlet Usage
        $this.SecurityRules.Add([SecurityRule]::new(
            "DeprecatedCmdletUsage",
            "Detects usage of deprecated cmdlets and methods that have security or compatibility issues",
            [SecuritySeverity]::Medium,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Pattern 1: New-Object System.Net.WebClient (deprecated - use Invoke-RestMethod/Invoke-WebRequest)
                $webClientCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].CommandElements.Count -ge 2 -and
                    $args[0].CommandElements[0].Value -eq 'New-Object' -and
                    $args[0].CommandElements[1].Value -match 'System\.Net\.WebClient'
                }, $true)
                
                foreach ($call in $webClientCalls) {
                    $violations += [SecurityViolation]::new(
                        "DeprecatedCmdletUsage",
                        "Using deprecated System.Net.WebClient. Use Invoke-RestMethod or Invoke-WebRequest instead.",
                        [SecuritySeverity]::Medium,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                # Pattern 2: Send-MailMessage (deprecated - security issues)
                $mailCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Send-MailMessage'
                }, $true)
                
                foreach ($call in $mailCalls) {
                    $violations += [SecurityViolation]::new(
                        "DeprecatedCmdletUsage",
                        "Send-MailMessage is deprecated and has security issues. Use MailKit or Microsoft.Graph instead.",
                        [SecuritySeverity]::High,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                # Pattern 3: WMI cmdlets (deprecated - use CIM cmdlets)
                $wmiCmdlets = @('Get-WmiObject', 'Set-WmiInstance', 'Invoke-WmiMethod', 'Remove-WmiObject', 'Register-WmiEvent')
                foreach ($cmdlet in $wmiCmdlets) {
                    $wmiCalls = $Ast.FindAll({
                        $args[0] -is [CommandAst] -and 
                        $args[0].GetCommandName() -eq $cmdlet
                    }, $true)
                    
                    foreach ($call in $wmiCalls) {
                        $cimEquivalent = $cmdlet -replace 'Wmi', 'Cim'
                        $violations += [SecurityViolation]::new(
                            "DeprecatedCmdletUsage",
                            "Using deprecated WMI cmdlet '$cmdlet'. Use CIM cmdlet '$cimEquivalent' instead.",
                            [SecuritySeverity]::Medium,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 4: Deprecated security protocols (SSL3, TLS 1.0, TLS 1.1)
                $securityProtocolAssignments = $Ast.FindAll({
                    $args[0] -is [AssignmentStatementAst] -and
                    $args[0].Left.Extent.Text -match 'SecurityProtocol'
                }, $true)
                
                foreach ($assignment in $securityProtocolAssignments) {
                    $rightSide = $assignment.Right.Extent.Text
                    if ($rightSide -match 'Ssl3|Tls\]|Tls11') {
                        $violations += [SecurityViolation]::new(
                            "DeprecatedCmdletUsage",
                            "Using deprecated security protocol (SSL3/TLS1.0/TLS1.1). Use TLS 1.2 or higher.",
                            [SecuritySeverity]::High,
                            $assignment.Extent.StartLineNumber,
                            $assignment.Extent.Text
                        )
                    }
                }
                
                # Pattern 5: Out-Printer (deprecated)
                $printerCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Out-Printer'
                }, $true)
                
                foreach ($call in $printerCalls) {
                    $violations += [SecurityViolation]::new(
                        "DeprecatedCmdletUsage",
                        "Out-Printer is deprecated. Use Start-Process with -Verb Print instead.",
                        [SecuritySeverity]::Low,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                # Pattern 6: New-WebServiceProxy (deprecated)
                $webServiceCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'New-WebServiceProxy'
                }, $true)
                
                foreach ($call in $webServiceCalls) {
                    $violations += [SecurityViolation]::new(
                        "DeprecatedCmdletUsage",
                        "New-WebServiceProxy is deprecated. Use Invoke-RestMethod for REST APIs or modern SOAP clients.",
                        [SecuritySeverity]::Medium,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                # Pattern 7: Export-Console (deprecated)
                $exportConsoleCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Export-Console'
                }, $true)
                
                foreach ($call in $exportConsoleCalls) {
                    $violations += [SecurityViolation]::new(
                        "DeprecatedCmdletUsage",
                        "Export-Console is deprecated. Use PowerShell modules instead of PSSnapins.",
                        [SecuritySeverity]::Low,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
                }
                
                # Pattern 8: Read-Host for passwords without -AsSecureString
                $readHostCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and 
                    $args[0].GetCommandName() -eq 'Read-Host'
                }, $true)
                
                foreach ($call in $readHostCalls) {
                    $callText = $call.Extent.Text.ToLower()
                    $isSensitive = $callText -match 'password|secret|key|token|credential|pin'
                    $hasAsSecureString = $callText -match '-assecurestring'
                    
                    if ($isSensitive -and -not $hasAsSecureString) {
                        $violations += [SecurityViolation]::new(
                            "DeprecatedCmdletUsage",
                            "Read-Host for sensitive data without -AsSecureString. Use -AsSecureString for passwords.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Pattern 9: [System.Web.Security.Membership]::GeneratePassword (deprecated)
                $generatePasswordCalls = $Ast.FindAll({
                    $args[0] -is [InvokeMemberExpressionAst] -and
                    $args[0].Expression.TypeName.Name -match 'System\.Web\.Security\.Membership' -and
                    $args[0].Member.Value -eq 'GeneratePassword'
                }, $true)
                
                foreach ($call in $generatePasswordCalls) {
                    $violations += [SecurityViolation]::new(
                        "DeprecatedCmdletUsage",
                        "[System.Web.Security.Membership]::GeneratePassword is deprecated. Use Get-Random or cryptographic RNG.",
                        [SecuritySeverity]::Medium,
                        $call.Extent.StartLineNumber,
                        $call.Extent.Text
                    )
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
            # Load suppressions for this file if parser is available
            if ($this.SuppressionParser) {
                try {
                    $this.SuppressionParser.ParseFile($ScriptPath)
                } catch {
                    Write-Warning "Failed to parse suppressions in ${ScriptPath}: $_"
                }
            }

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
                # Check if rule is disabled in configuration
                if ($this.PowerShieldConfig -and $this.PowerShieldConfig.Rules.ContainsKey($rule.Name)) {
                    $ruleConfig = $this.PowerShieldConfig.Rules[$rule.Name]
                    if ($ruleConfig.enabled -eq $false) {
                        Write-Verbose "Rule $($rule.Name) is disabled in configuration"
                        continue
                    }
                    
                    # Override severity if specified in config
                    if ($ruleConfig.severity) {
                        try {
                            $rule.Severity = [SecuritySeverity]::Parse([SecuritySeverity], $ruleConfig.severity)
                        } catch {
                            Write-Warning "Invalid severity '$($ruleConfig.severity)' for rule $($rule.Name)"
                        }
                    }
                }
                
                try {
                    $ruleViolations = $rule.Evaluate($ast, $ScriptPath)
                    # Filter out null or invalid violations
                    if ($ruleViolations) {
                        foreach ($violation in $ruleViolations) {
                            if ($violation -and $violation.Name) {
                                # Check if violation is suppressed
                                $isSuppressed = $false
                                if ($this.SuppressionParser) {
                                    try {
                                        $isSuppressed = $this.SuppressionParser.IsSuppressed($violation.RuleId, $violation.LineNumber)
                                    } catch {
                                        Write-Debug "Suppression check failed: $_"
                                    }
                                }
                                
                                if (-not $isSuppressed) {
                                    $allViolations += $violation
                                } else {
                                    Write-Verbose "Violation at line $($violation.LineNumber) is suppressed"
                                }
                            }
                        }
                    }
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
        $normalizedFilePath = $FilePath.Replace('\', '/')
        if ($normalizedFilePath.StartsWith('./')) {
            $normalizedFilePath = $normalizedFilePath.Substring(2)
        }
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
    .PARAMETER WorkspacePath
        Path to workspace for loading configuration
    .PARAMETER EnableSuppressions
        Enable suppression comment parsing
    #>
    param(
        [Parameter(Mandatory=$false)]
        [string]$WorkspacePath = '.',
        
        [Parameter(Mandatory=$false)]
        [switch]$EnableSuppressions
    )
    
    $analyzer = [PowerShellSecurityAnalyzer]::new()
    
    # Try to load configuration
    try {
        $analyzer.LoadConfiguration($WorkspacePath)
    } catch {
        Write-Warning "Failed to load configuration: $_"
    }
    
    # Initialize suppression parser if requested
    if ($EnableSuppressions -and $analyzer.PowerShieldConfig) {
        try {
            $modulePath = Join-Path $PSScriptRoot 'SuppressionParser.psm1'
            if (Test-Path $modulePath) {
                Import-Module $modulePath -Force -ErrorAction Stop
                $analyzer.SuppressionParser = New-SuppressionParser `
                    -RequireJustification $analyzer.PowerShieldConfig.Suppressions.require_justification `
                    -MaxDurationDays $analyzer.PowerShieldConfig.Suppressions.max_duration_days `
                    -AllowPermanent $analyzer.PowerShieldConfig.Suppressions.allow_permanent
            }
        } catch {
            Write-Warning "Failed to initialize suppression parser: $_"
        }
    }
    
    return $analyzer
}

function Invoke-SecurityAnalysis {
    <#
    .SYNOPSIS
        Analyzes a PowerShell script for security violations
    .PARAMETER ScriptPath
        Path to the PowerShell script to analyze
    .PARAMETER WorkspacePath
        Path to workspace for loading configuration
    .PARAMETER EnableSuppressions
        Enable suppression comment parsing
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ScriptPath,
        
        [Parameter(Mandatory=$false)]
        [string]$WorkspacePath = '.',
        
        [Parameter(Mandatory=$false)]
        [switch]$EnableSuppressions
    )
    
    $analyzer = New-SecurityAnalyzer -WorkspacePath $WorkspacePath -EnableSuppressions:$EnableSuppressions
    return $analyzer.AnalyzeScript($ScriptPath)
}

function Invoke-WorkspaceAnalysis {
    <#
    .SYNOPSIS
        Analyzes all PowerShell scripts in a workspace
    .PARAMETER WorkspacePath
        Path to the workspace directory
    .PARAMETER EnableSuppressions
        Enable suppression comment parsing
    #>
    param(
        [Parameter(Mandatory)]
        [string]$WorkspacePath,
        
        [Parameter(Mandatory=$false)]
        [switch]$EnableSuppressions
    )
    
    $analyzer = New-SecurityAnalyzer -WorkspacePath $WorkspacePath -EnableSuppressions:$EnableSuppressions
    return $analyzer.AnalyzeWorkspace($WorkspacePath)
}

# Export module members
Export-ModuleMember -Function New-SecurityAnalyzer, Invoke-SecurityAnalysis, Invoke-WorkspaceAnalysis
