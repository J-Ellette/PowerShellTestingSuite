#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    PSTS CLI - PowerShield Testing Suite Command Line Interface
.DESCRIPTION
    Comprehensive command-line interface for PowerShield security analysis,
    configuration management, baseline tracking, and fix management.
.NOTES
    Version: 1.2.0
    Author: PowerShield Project
.EXAMPLE
    psts analyze ./scripts
    psts analyze --format sarif --output results.sarif
    psts baseline create
    psts fix preview
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $false)]
    [ValidateSet('analyze', 'config', 'baseline', 'fix', 'install-hooks', 'version', 'help', 'interactive')]
    [string]$Command,
    
    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

# Script directory
$scriptRoot = $PSScriptRoot

# Color helper functions
function Write-Success { param([string]$Message) Write-Host "✓ $Message" -ForegroundColor Green }
function Write-Info { param([string]$Message) Write-Host "ℹ $Message" -ForegroundColor Cyan }
function Write-Warning { param([string]$Message) Write-Host "⚠ $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "✗ $Message" -ForegroundColor Red }
function Write-Header { param([string]$Message) Write-Host "`n$Message" -ForegroundColor Cyan }

# Import modules
try {
    # POWERSHIELD-SUPPRESS-NEXT: DangerousModules - Controlled path within repository
    Import-Module "$scriptRoot/src/PowerShellSecurityAnalyzer.psm1" -Force -ErrorAction Stop
    # POWERSHIELD-SUPPRESS-NEXT: DangerousModules - Controlled path within repository
    Import-Module "$scriptRoot/src/ConfigLoader.psm1" -Force -ErrorAction Stop
} catch {
    Write-Error "Failed to load PowerShield modules: $_"
    exit 1
}

#region Command Functions

function Invoke-Analyze {
    <#
    .SYNOPSIS
        Analyze PowerShell scripts for security violations
    .PARAMETER Path
        Path to file or directory to analyze (default: current directory)
    .PARAMETER Format
        Output format: json, sarif, markdown, text (default: text)
    .PARAMETER Output
        Output file path for results
    .PARAMETER Baseline
        Compare against baseline file
    .PARAMETER EnableSuppressions
        Enable suppression comment processing
    #>
    param(
        [string]$Path = ".",
        [ValidateSet('json', 'sarif', 'markdown', 'text')]
        [string]$Format = 'text',
        [string]$Output,
        [string]$Baseline,
        [switch]$EnableSuppressions
    )
    
    $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
    if (-not $targetPath) {
        Write-Error "Path not found: $Path"
        exit 1
    }
    
    Write-Info "Analyzing: $targetPath"
    
    # Load configuration
    try {
        $config = Import-PowerShieldConfiguration -WorkspacePath $scriptRoot
    } catch {
        Write-Warning "No configuration found, using defaults"
        $config = $null
    }
    
    # Analyze
    if (Test-Path $targetPath -PathType Container) {
        $result = Invoke-WorkspaceAnalysis -WorkspacePath $targetPath -EnableSuppressions:$EnableSuppressions
    } else {
        $singleResult = Invoke-SecurityAnalysis -ScriptPath $targetPath -EnableSuppressions:$EnableSuppressions
        $result = @{
            Results = @($singleResult)
            Summary = @{
                TotalCritical = ($singleResult.Violations | Where-Object { $_.Severity -eq 'Critical' }).Count
                TotalHigh = ($singleResult.Violations | Where-Object { $_.Severity -eq 'High' }).Count
                TotalMedium = ($singleResult.Violations | Where-Object { $_.Severity -eq 'Medium' }).Count
                TotalLow = ($singleResult.Violations | Where-Object { $_.Severity -eq 'Low' }).Count
            }
            TotalViolations = $singleResult.Violations.Count
            TotalFiles = 1
        }
    }
    
    # Handle baseline comparison if requested
    if ($Baseline) {
        if (-not (Test-Path $Baseline)) {
            Write-Error "Baseline file not found: $Baseline"
            exit 1
        }
        
        $baselineData = Get-Content $Baseline -Raw | ConvertFrom-Json
        $result = Compare-WithBaseline -CurrentResult $result -BaselineResult $baselineData
    }
    
    # Display results
    if ($Format -eq 'text') {
        Show-AnalysisResults -Result $result
    }
    
    # Export results if requested
    if ($Output) {
        Export-AnalysisResults -Result $result -Format $Format -OutputFile $Output
    }
    
    # Exit with appropriate code
    if ($config -and $config.CI -and $config.CI.fail_on) {
        $shouldFail = $false
        foreach ($severity in $config.CI.fail_on) {
            $count = $result.Summary["Total$severity"]
            if ($count -gt 0) {
                $shouldFail = $true
                break
            }
        }
        if ($shouldFail) {
            Write-Error "Analysis failed due to violations matching fail_on criteria"
            exit 1
        }
    }
    
    exit 0
}

function Show-AnalysisResults {
    param($Result)
    
    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "PowerShield Security Analysis Results" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    
    Write-Host "`nFiles Analyzed: $($Result.TotalFiles)" -ForegroundColor White
    Write-Host "Total Violations: $($Result.TotalViolations)" -ForegroundColor White
    
    if ($Result.Summary) {
        Write-Host "`nSeverity Breakdown:" -ForegroundColor White
        foreach ($severity in @('Critical', 'High', 'Medium', 'Low')) {
            $count = $Result.Summary["Total$severity"]
            if ($count -gt 0) {
                $color = switch ($severity) {
                    'Critical' { 'Red' }
                    'High' { 'Red' }
                    'Medium' { 'Yellow' }
                    'Low' { 'Gray' }
                }
                Write-Host "  $severity`: $count" -ForegroundColor $color
            }
        }
    }
    
    # Show violations
    if ($Result.TotalViolations -gt 0) {
        $allViolations = @()
        foreach ($fileResult in $Result.Results) {
            if ($fileResult.Violations) {
                $allViolations += $fileResult.Violations
            }
        }
        
        $topViolations = $allViolations | Sort-Object -Property Severity -Descending | Select-Object -First 10
        
        Write-Host "`nTop Issues:" -ForegroundColor White
        foreach ($violation in $topViolations) {
            $severityColor = switch ($violation.Severity) {
                'Critical' { 'Red' }
                'High' { 'Red' }
                'Medium' { 'Yellow' }
                'Low' { 'Gray' }
                default { 'White' }
            }
            
            Write-Host "`n  [$($violation.Severity)] $($violation.FilePath):$($violation.LineNumber)" -ForegroundColor $severityColor
            Write-Host "    $($violation.RuleId): $($violation.Message)" -ForegroundColor Gray
            if ($violation.Code) {
                Write-Host "    Code: $($violation.Code)" -ForegroundColor DarkGray
            }
        }
        
        if ($allViolations.Count -gt 10) {
            Write-Host "`n  ... and $($allViolations.Count - 10) more violations" -ForegroundColor Gray
        }
    } else {
        Write-Success "`nNo security violations found!"
    }
    
    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
}

function Export-AnalysisResults {
    param(
        $Result,
        [string]$Format,
        [string]$OutputFile
    )
    
    switch ($Format) {
        'json' {
            $Result | ConvertTo-Json -Depth 10 | Out-File $OutputFile
            Write-Success "Results exported to: $OutputFile"
        }
        'sarif' {
            # POWERSHIELD-SUPPRESS-NEXT: UnsafeFileInclusion - Controlled path within repository
            . "$scriptRoot/scripts/Convert-ToSARIF.ps1"
            $jsonTemp = [System.IO.Path]::GetTempFileName()
            $Result | ConvertTo-Json -Depth 10 | Out-File $jsonTemp
            Convert-ToSARIF -InputFile $jsonTemp -OutputFile $OutputFile
            Remove-Item $jsonTemp -Force
            Write-Success "SARIF results exported to: $OutputFile"
        }
        'markdown' {
            # POWERSHIELD-SUPPRESS-NEXT: UnsafeFileInclusion - Controlled path within repository
            . "$scriptRoot/scripts/Generate-SecurityReport.ps1"
            $jsonTemp = [System.IO.Path]::GetTempFileName()
            $Result | ConvertTo-Json -Depth 10 | Out-File $jsonTemp
            Generate-SecurityReport -InputFile $jsonTemp -OutputFile $OutputFile
            Remove-Item $jsonTemp -Force
            Write-Success "Markdown report exported to: $OutputFile"
        }
    }
}

function Compare-WithBaseline {
    param($CurrentResult, $BaselineResult)
    
    Write-Info "Comparing with baseline..."
    
    # Extract all violations from current result
    $currentViolations = @()
    foreach ($fileResult in $CurrentResult.Results) {
        if ($fileResult.Violations) {
            $currentViolations += $fileResult.Violations
        }
    }
    
    # Extract baseline violations
    $baselineViolations = @()
    if ($BaselineResult.Results) {
        foreach ($fileResult in $BaselineResult.Results) {
            if ($fileResult.Violations) {
                $baselineViolations += $fileResult.Violations
            }
        }
    } elseif ($BaselineResult.violations) {
        $baselineViolations = $BaselineResult.violations
    }
    
    # Find new violations
    $newViolations = @()
    foreach ($current in $currentViolations) {
        $found = $false
        foreach ($baseline in $baselineViolations) {
            if ($current.RuleId -eq $baseline.RuleId -and 
                $current.FilePath -eq $baseline.FilePath -and 
                $current.LineNumber -eq $baseline.LineNumber) {
                $found = $true
                break
            }
        }
        if (-not $found) {
            $newViolations += $current
        }
    }
    
    # Find fixed violations
    $fixedViolations = @()
    foreach ($baseline in $baselineViolations) {
        $found = $false
        foreach ($current in $currentViolations) {
            if ($baseline.RuleId -eq $current.RuleId -and 
                $baseline.FilePath -eq $current.FilePath -and 
                $baseline.LineNumber -eq $current.LineNumber) {
                $found = $true
                break
            }
        }
        if (-not $found) {
            $fixedViolations += $baseline
        }
    }
    
    # Add comparison info
    $CurrentResult.BaselineComparison = @{
        NewViolations = $newViolations
        FixedViolations = $fixedViolations
        TotalNew = $newViolations.Count
        TotalFixed = $fixedViolations.Count
    }
    
    Write-Info "New violations: $($newViolations.Count)"
    Write-Info "Fixed violations: $($fixedViolations.Count)"
    
    return $CurrentResult
}

function Invoke-Config {
    <#
    .SYNOPSIS
        Configuration management commands
    .PARAMETER SubCommand
        validate - Validate configuration file
        init - Create default configuration
        show - Display current configuration
    #>
    param([string]$SubCommand)
    
    switch ($SubCommand) {
        'validate' {
            Write-Info "Validating PowerShield configuration..."
            try {
                $config = Import-PowerShieldConfiguration -WorkspacePath $scriptRoot
                Write-Success "Configuration is valid"
                Write-Host "`nConfiguration Summary:"
                Write-Host "  Version: $($config.Version)"
                Write-Host "  Severity Threshold: $($config.Analysis.severity_threshold)"
                Write-Host "  Parallel Analysis: $($config.Analysis.parallel_analysis)"
                Write-Host "  Auto-Fix Enabled: $($config.AutoFix.enabled)"
                if ($config.Hooks) {
                    Write-Host "  Hooks Enabled: $($config.Hooks.enabled)"
                }
            } catch {
                Write-Error "Configuration validation failed: $_"
                exit 1
            }
        }
        'show' {
            try {
                $config = Import-PowerShieldConfiguration -WorkspacePath $scriptRoot
                $config | ConvertTo-Json -Depth 10
            } catch {
                Write-Error "Failed to load configuration: $_"
                exit 1
            }
        }
        'init' {
            $configPath = Join-Path (Get-Location) ".powershield.yml"
            if (Test-Path $configPath) {
                Write-Warning "Configuration already exists: $configPath"
                $response = Read-Host "Overwrite? (y/N)"
                if ($response -ne 'y' -and $response -ne 'Y') {
                    exit 0
                }
            }
            
            $examplePath = Join-Path $scriptRoot ".powershield.yml.example"
            if (Test-Path $examplePath) {
                Copy-Item $examplePath $configPath
                Write-Success "Created configuration file: $configPath"
                Write-Info "Edit this file to customize PowerShield behavior"
            } else {
                Write-Error "Example configuration not found"
                exit 1
            }
        }
        default {
            Write-Error "Unknown config subcommand: $SubCommand"
            Write-Info "Available subcommands: validate, show, init"
            exit 1
        }
    }
}

function Invoke-Baseline {
    <#
    .SYNOPSIS
        Baseline management commands
    .PARAMETER SubCommand
        create - Create baseline from current analysis
        compare - Compare current state with baseline
    #>
    param(
        [string]$SubCommand,
        [string]$Path = ".",
        [string]$Output
    )
    
    switch ($SubCommand) {
        'create' {
            Write-Info "Creating baseline from current analysis..."
            
            $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
            if (-not $targetPath) {
                Write-Error "Path not found: $Path"
                exit 1
            }
            
            # Perform analysis
            if (Test-Path $targetPath -PathType Container) {
                $result = Invoke-WorkspaceAnalysis -WorkspacePath $targetPath
            } else {
                $singleResult = Invoke-SecurityAnalysis -ScriptPath $targetPath
                $result = @{
                    Results = @($singleResult)
                    Summary = @{
                        TotalCritical = ($singleResult.Violations | Where-Object { $_.Severity -eq 'Critical' }).Count
                        TotalHigh = ($singleResult.Violations | Where-Object { $_.Severity -eq 'High' }).Count
                        TotalMedium = ($singleResult.Violations | Where-Object { $_.Severity -eq 'Medium' }).Count
                        TotalLow = ($singleResult.Violations | Where-Object { $_.Severity -eq 'Low' }).Count
                    }
                    TotalViolations = $singleResult.Violations.Count
                    TotalFiles = 1
                }
            }
            
            # Add metadata
            $baselineData = @{
                Version = "1.0"
                CreatedAt = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
                BasePath = $targetPath.Path
                Results = $result
            }
            
            # Determine output file
            $baselineFile = if ($Output) { $Output } else { ".powershield-baseline.json" }
            
            # Export baseline
            $baselineData | ConvertTo-Json -Depth 10 | Out-File $baselineFile
            Write-Success "Baseline created: $baselineFile"
            Write-Info "Files analyzed: $($result.TotalFiles)"
            Write-Info "Total violations: $($result.TotalViolations)"
        }
        'compare' {
            Write-Info "Comparing current state with baseline..."
            
            # Find baseline file
            $baselineFile = if ($Output) { $Output } else { ".powershield-baseline.json" }
            if (-not (Test-Path $baselineFile)) {
                Write-Error "Baseline file not found: $baselineFile"
                Write-Info "Create a baseline first with: psts baseline create"
                exit 1
            }
            
            $baselineData = Get-Content $baselineFile -Raw | ConvertFrom-Json
            
            $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
            if (-not $targetPath) {
                Write-Error "Path not found: $Path"
                exit 1
            }
            
            # Perform current analysis
            if (Test-Path $targetPath -PathType Container) {
                $currentResult = Invoke-WorkspaceAnalysis -WorkspacePath $targetPath
            } else {
                $singleResult = Invoke-SecurityAnalysis -ScriptPath $targetPath
                $currentResult = @{
                    Results = @($singleResult)
                    TotalViolations = $singleResult.Violations.Count
                    TotalFiles = 1
                }
            }
            
            # Compare
            $comparison = Compare-WithBaseline -CurrentResult $currentResult -BaselineResult $baselineData.Results
            
            # Display comparison results
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            Write-Host "Baseline Comparison Results" -ForegroundColor Cyan
            Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            
            Write-Host "`nBaseline Created: $($baselineData.CreatedAt)" -ForegroundColor Gray
            Write-Host "Baseline Violations: $($baselineData.Results.TotalViolations)" -ForegroundColor White
            Write-Host "Current Violations: $($currentResult.TotalViolations)" -ForegroundColor White
            
            if ($comparison.BaselineComparison.TotalFixed -gt 0) {
                Write-Host "`n✓ Fixed Issues: $($comparison.BaselineComparison.TotalFixed)" -ForegroundColor Green
            }
            
            if ($comparison.BaselineComparison.TotalNew -gt 0) {
                Write-Host "✗ New Issues: $($comparison.BaselineComparison.TotalNew)" -ForegroundColor Red
                
                Write-Host "`nNew Violations:" -ForegroundColor White
                foreach ($violation in $comparison.BaselineComparison.NewViolations | Select-Object -First 10) {
                    $severityColor = switch ($violation.Severity) {
                        'Critical' { 'Red' }
                        'High' { 'Red' }
                        'Medium' { 'Yellow' }
                        'Low' { 'Gray' }
                        default { 'White' }
                    }
                    Write-Host "  [$($violation.Severity)] $($violation.FilePath):$($violation.LineNumber)" -ForegroundColor $severityColor
                    Write-Host "    $($violation.RuleId): $($violation.Message)" -ForegroundColor Gray
                }
                
                if ($comparison.BaselineComparison.TotalNew -gt 10) {
                    Write-Host "  ... and $($comparison.BaselineComparison.TotalNew - 10) more new violations" -ForegroundColor Gray
                }
            } else {
                Write-Success "`nNo new violations found!"
            }
            
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            
            # Exit with error if new violations found
            if ($comparison.BaselineComparison.TotalNew -gt 0) {
                exit 1
            }
        }
        default {
            Write-Error "Unknown baseline subcommand: $SubCommand"
            Write-Info "Available subcommands: create, compare"
            exit 1
        }
    }
}

function Invoke-Fix {
    <#
    .SYNOPSIS
        Fix management commands
    .PARAMETER SubCommand
        preview - Preview available fixes without applying
        apply - Apply fixes with confidence threshold
    #>
    param(
        [string]$SubCommand,
        [string]$Path = ".",
        [double]$Confidence = 0.8,
        [string]$ViolationsFile
    )
    
    switch ($SubCommand) {
        'preview' {
            Write-Info "Previewing available fixes..."
            
            # Find or create violations file
            if (-not $ViolationsFile) {
                $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
                if (-not $targetPath) {
                    Write-Error "Path not found: $Path"
                    exit 1
                }
                
                # Perform analysis
                if (Test-Path $targetPath -PathType Container) {
                    $result = Invoke-WorkspaceAnalysis -WorkspacePath $targetPath
                } else {
                    $singleResult = Invoke-SecurityAnalysis -ScriptPath $targetPath
                    $result = @{
                        Results = @($singleResult)
                    }
                }
                
                # Collect violations
                $allViolations = @()
                foreach ($fileResult in $result.Results) {
                    if ($fileResult.Violations) {
                        $allViolations += $fileResult.Violations
                    }
                }
            } else {
                if (-not (Test-Path $ViolationsFile)) {
                    Write-Error "Violations file not found: $ViolationsFile"
                    exit 1
                }
                $violationsData = Get-Content $ViolationsFile -Raw | ConvertFrom-Json
                $allViolations = $violationsData.violations
            }
            
            if ($allViolations.Count -eq 0) {
                Write-Success "No violations found that need fixing!"
                exit 0
            }
            
            # Load configuration for auto-fix settings
            try {
                $config = Import-PowerShieldConfiguration -WorkspacePath $scriptRoot
            } catch {
                Write-Warning "No configuration found, using defaults"
                $config = @{
                    AutoFix = @{
                        enabled = $true
                        confidence_threshold = 0.8
                        rule_fixes = @{}
                    }
                }
            }
            
            # Filter fixable violations
            $fixableViolations = @()
            foreach ($violation in $allViolations) {
                # Check if fixes are enabled for this rule
                $ruleFixEnabled = $true
                if ($config.AutoFix.rule_fixes -and $config.AutoFix.rule_fixes.ContainsKey($violation.RuleId)) {
                    $ruleFixEnabled = $config.AutoFix.rule_fixes[$violation.RuleId]
                }
                
                if ($ruleFixEnabled) {
                    $fixableViolations += $violation
                }
            }
            
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            Write-Host "Fix Preview" -ForegroundColor Cyan
            Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            
            Write-Host "`nTotal Violations: $($allViolations.Count)" -ForegroundColor White
            Write-Host "Fixable Violations: $($fixableViolations.Count)" -ForegroundColor White
            Write-Host "Confidence Threshold: $Confidence" -ForegroundColor White
            
            if ($fixableViolations.Count -gt 0) {
                Write-Host "`nFixable Issues:" -ForegroundColor White
                
                $grouped = $fixableViolations | Group-Object RuleId
                foreach ($group in $grouped) {
                    Write-Host "`n  Rule: $($group.Name)" -ForegroundColor Cyan
                    Write-Host "  Count: $($group.Count)" -ForegroundColor White
                    
                    foreach ($violation in $group.Group | Select-Object -First 3) {
                        Write-Host "    • $($violation.FilePath):$($violation.LineNumber)" -ForegroundColor Gray
                    }
                    
                    if ($group.Count -gt 3) {
                        Write-Host "    ... and $($group.Count - 3) more" -ForegroundColor DarkGray
                    }
                }
                
                Write-Host "`n💡 To apply fixes, run:" -ForegroundColor Yellow
                Write-Host "   psts fix apply --confidence $Confidence" -ForegroundColor White
            } else {
                Write-Info "No fixable violations found (check auto-fix configuration)"
            }
            
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
        }
        'apply' {
            Write-Info "Applying fixes with confidence threshold: $Confidence"
            Write-Warning "Note: This feature requires the PowerShield auto-fix action to be configured"
            Write-Info "For manual fix application, use the GitHub Actions workflow or run:"
            Write-Info "  pwsh -File actions/copilot-autofix/apply-fixes.ps1"
            
            # This would typically be handled by the GitHub Action
            # For local use, we provide instructions
            Write-Host "`nTo apply fixes locally:" -ForegroundColor Cyan
            Write-Host "1. Ensure violations file exists (run psts analyze first)" -ForegroundColor White
            Write-Host "2. Configure AI provider in .powershield.yml" -ForegroundColor White
            Write-Host "3. Run the auto-fix action through GitHub Actions workflow" -ForegroundColor White
        }
        default {
            Write-Error "Unknown fix subcommand: $SubCommand"
            Write-Info "Available subcommands: preview, apply"
            exit 1
        }
    }
}

function Install-Hooks {
    <#
    .SYNOPSIS
        Install PowerShield pre-commit hook
    #>
    param([switch]$Force)
    
    $gitDir = git rev-parse --git-dir 2>$null
    if (-not $gitDir) {
        Write-Error "Not a git repository"
        exit 1
    }
    
    $gitDir = Resolve-Path $gitDir
    $hooksDir = Join-Path $gitDir "hooks"
    $targetHook = Join-Path $hooksDir "pre-commit"
    $sourceHook = Join-Path $scriptRoot ".powershield/hooks/pre-commit"
    
    if (-not (Test-Path $sourceHook)) {
        Write-Error "Hook source not found: $sourceHook"
        exit 1
    }
    
    # Create hooks directory if it doesn't exist
    if (-not (Test-Path $hooksDir)) {
        New-Item -ItemType Directory -Path $hooksDir -Force | Out-Null
    }
    
    # Check if hook already exists
    if ((Test-Path $targetHook) -and -not $Force) {
        Write-Warning "Pre-commit hook already exists at: $targetHook"
        Write-Info "Use --force to overwrite"
        
        $response = Read-Host "Do you want to overwrite? (y/N)"
        if ($response -ne 'y' -and $response -ne 'Y') {
            Write-Info "Installation cancelled"
            exit 0
        }
    }
    
    # Copy hook
    try {
        Copy-Item $sourceHook $targetHook -Force
        
        # Make executable on Unix-like systems
        if ($IsLinux -or $IsMacOS) {
            chmod +x $targetHook
        }
        
        Write-Success "Pre-commit hook installed successfully"
        Write-Info "Location: $targetHook"
        Write-Host "`nThe hook will:"
        Write-Host "  • Analyze staged PowerShell files before each commit"
        Write-Host "  • Block commits with Critical/High severity violations"
        Write-Host "  • Can be bypassed with: git commit --no-verify"
        Write-Host "`nConfigure in .powershield.yml:"
        Write-Host "  hooks:"
        Write-Host "    enabled: true"
        Write-Host "    block_on: ['Critical', 'High']"
        
    } catch {
        Write-Error "Failed to install hook: $_"
        exit 1
    }
}

function Show-Version {
    <#
    .SYNOPSIS
        Display PowerShield version information
    #>
    Write-Host "PowerShield - Comprehensive PowerShell Security Platform" -ForegroundColor Cyan
    Write-Host "Version: 1.2.0" -ForegroundColor White
    Write-Host "PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
    Write-Host "Platform: $($PSVersionTable.Platform)" -ForegroundColor Gray
    Write-Host "`nCLI: psts (PowerShield Testing Suite)" -ForegroundColor Gray
    Write-Host "Repository: https://github.com/J-Ellette/PowerShield" -ForegroundColor Gray
}

function Invoke-InteractiveMode {
    <#
    .SYNOPSIS
        Run PowerShield in interactive mode
    #>
    
    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "PowerShield Interactive Mode" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    
    Write-Host "`nWelcome to PowerShield! This interactive mode helps you get started." -ForegroundColor White
    Write-Host "Type 'exit' or 'quit' at any time to leave interactive mode.`n" -ForegroundColor Gray
    
    # Menu options
    $maxMenuOption = 7
    
    while ($true) {
        Write-Host "`nWhat would you like to do?" -ForegroundColor Cyan
        Write-Host "  1. Analyze files for security issues" -ForegroundColor White
        Write-Host "  2. Create or manage baseline" -ForegroundColor White
        Write-Host "  3. Preview available fixes" -ForegroundColor White
        Write-Host "  4. Configure PowerShield" -ForegroundColor White
        Write-Host "  5. Install pre-commit hooks" -ForegroundColor White
        Write-Host "  6. Show help" -ForegroundColor White
        Write-Host "  7. Exit" -ForegroundColor White
        
        $choice = Read-Host "`nEnter your choice (1-$maxMenuOption)"
        
        switch ($choice) {
            '1' {
                # Analyze
                Write-Host "`n[Analyze Mode]" -ForegroundColor Cyan
                $path = Read-Host "Enter path to analyze (default: current directory)"
                if (-not $path) { $path = "." }
                
                $formatChoice = Read-Host "Output format? (1=text, 2=json, 3=sarif, 4=markdown) [default: text]"
                $format = switch ($formatChoice) {
                    '2' { 'json' }
                    '3' { 'sarif' }
                    '4' { 'markdown' }
                    default { 'text' }
                }
                
                $outputFile = $null
                if ($format -ne 'text') {
                    $outputFile = Read-Host "Output file path (optional, press Enter to skip)"
                    if (-not $outputFile) { $outputFile = $null }
                }
                
                Write-Host "`nRunning analysis..." -ForegroundColor Yellow
                $params = @{ Path = $path; Format = $format }
                if ($outputFile) { $params['Output'] = $outputFile }
                
                try {
                    Invoke-Analyze @params
                } catch {
                    Write-Error "Analysis failed: $_"
                }
            }
            '2' {
                # Baseline
                Write-Host "`n[Baseline Mode]" -ForegroundColor Cyan
                Write-Host "  1. Create new baseline" -ForegroundColor White
                Write-Host "  2. Compare with existing baseline" -ForegroundColor White
                
                $baselineChoice = Read-Host "Enter choice (1-2)"
                
                if ($baselineChoice -eq '1') {
                    $path = Read-Host "Enter path to analyze (default: current directory)"
                    if (-not $path) { $path = "." }
                    
                    Write-Host "`nCreating baseline..." -ForegroundColor Yellow
                    try {
                        Invoke-Baseline -SubCommand 'create' -Path $path
                    } catch {
                        Write-Error "Baseline creation failed: $_"
                    }
                } elseif ($baselineChoice -eq '2') {
                    $path = Read-Host "Enter path to analyze (default: current directory)"
                    if (-not $path) { $path = "." }
                    
                    Write-Host "`nComparing with baseline..." -ForegroundColor Yellow
                    try {
                        Invoke-Baseline -SubCommand 'compare' -Path $path
                    } catch {
                        Write-Error "Baseline comparison failed: $_"
                    }
                } else {
                    Write-Warning "Invalid choice"
                }
            }
            '3' {
                # Fix preview
                Write-Host "`n[Fix Preview Mode]" -ForegroundColor Cyan
                $path = Read-Host "Enter path to analyze (default: current directory)"
                if (-not $path) { $path = "." }
                
                $confidenceInput = Read-Host "Confidence threshold (0.0-1.0, default: 0.8)"
                $confidence = 0.8
                if ($confidenceInput) {
                    try {
                        $parsedConfidence = [double]$confidenceInput
                        if ($parsedConfidence -ge 0.0 -and $parsedConfidence -le 1.0) {
                            $confidence = $parsedConfidence
                        } else {
                            Write-Warning "Invalid confidence value. Using default: 0.8"
                        }
                    } catch {
                        Write-Warning "Invalid confidence value. Using default: 0.8"
                    }
                }
                
                Write-Host "`nPreviewing fixes..." -ForegroundColor Yellow
                try {
                    Invoke-Fix -SubCommand 'preview' -Path $path -Confidence $confidence
                } catch {
                    Write-Error "Fix preview failed: $_"
                }
            }
            '4' {
                # Configuration
                Write-Host "`n[Configuration Mode]" -ForegroundColor Cyan
                Write-Host "  1. Validate configuration" -ForegroundColor White
                Write-Host "  2. Show configuration" -ForegroundColor White
                Write-Host "  3. Initialize configuration" -ForegroundColor White
                
                $configChoice = Read-Host "Enter choice (1-3)"
                
                try {
                    switch ($configChoice) {
                        '1' { Invoke-Config -SubCommand 'validate' }
                        '2' { Invoke-Config -SubCommand 'show' }
                        '3' { Invoke-Config -SubCommand 'init' }
                        default { Write-Warning "Invalid choice" }
                    }
                } catch {
                    Write-Error "Configuration operation failed: $_"
                }
            }
            '5' {
                # Install hooks
                Write-Host "`n[Install Hooks Mode]" -ForegroundColor Cyan
                $confirm = Read-Host "Install pre-commit hooks? (y/N)"
                
                if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                    try {
                        Install-Hooks
                    } catch {
                        Write-Error "Hook installation failed: $_"
                    }
                }
            }
            '6' {
                # Help
                Show-Help
            }
            '7' {
                # Exit
                Write-Host "`nExiting PowerShield interactive mode. Goodbye!" -ForegroundColor Cyan
                return
            }
            'exit' {
                Write-Host "`nExiting PowerShield interactive mode. Goodbye!" -ForegroundColor Cyan
                return
            }
            'quit' {
                Write-Host "`nExiting PowerShield interactive mode. Goodbye!" -ForegroundColor Cyan
                return
            }
            default {
                Write-Warning "Invalid choice. Please enter a number from 1-$maxMenuOption."
            }
        }
    }
}

function Show-Help {
    <#
    .SYNOPSIS
        Display help information
    #>
    Write-Host @"
PowerShield Testing Suite (psts) - Comprehensive PowerShell Security Platform

USAGE:
    psts <command> [options]

COMMANDS:
    
    analyze [path]                Analyze PowerShell scripts for security violations
        Options:
            --format <type>       Output format: json, sarif, markdown, text (default: text)
            --output <file>       Output file path for results
            --baseline <file>     Compare against baseline file
            --suppressions        Enable suppression comment processing
        
        Examples:
            psts analyze                           # Analyze current directory
            psts analyze ./scripts                 # Analyze specific path
            psts analyze --format sarif            # Output in SARIF format
            psts analyze --output results.json --format json
            psts analyze --baseline .powershield-baseline.json
    
    config <subcommand>           Configuration management
        Subcommands:
            validate              Validate configuration file
            show                  Display current configuration (JSON)
            init                  Create default configuration file
        
        Examples:
            psts config validate                   # Validate .powershield.yml
            psts config show                       # Show current config
            psts config init                       # Create default config
    
    baseline <subcommand>         Baseline management
        Subcommands:
            create [path]         Create baseline from current analysis
            compare [path]        Compare current state with baseline
        
        Options:
            --output <file>       Custom baseline file path (default: .powershield-baseline.json)
        
        Examples:
            psts baseline create                   # Create baseline
            psts baseline create --output custom-baseline.json
            psts baseline compare                  # Compare with baseline
            psts baseline compare ./scripts        # Compare specific path
    
    fix <subcommand>              Fix management
        Subcommands:
            preview [path]        Preview available fixes without applying
            apply [path]          Apply fixes with confidence threshold
        
        Options:
            --confidence <0-1>    Confidence threshold (default: 0.8)
            --violations <file>   Path to violations file
        
        Examples:
            psts fix preview                       # Preview all fixable issues
            psts fix preview --confidence 0.9      # Higher confidence threshold
            psts fix apply --confidence 0.8        # Apply fixes
    
    install-hooks                 Install pre-commit hook for local validation
        Options:
            --force               Overwrite existing hook
        
        Examples:
            psts install-hooks                     # Install hook interactively
            psts install-hooks --force             # Force overwrite
    
    version                       Display version information
    
    interactive                   Run in interactive mode with guided prompts
    
    help                          Display this help message

CONFIGURATION:
    PowerShield uses .powershield.yml for configuration. Create one with:
        psts config init
    
    Configuration file locations (in priority order):
        1. .powershield.yml (current directory)
        2. .powershield.yml (repository root)
        3. ~/.powershield.yml (user home)

EXAMPLES:
    # Quick security scan
    psts analyze
    
    # Detailed analysis with SARIF output
    psts analyze ./src --format sarif --output security-results.sarif
    
    # Create baseline and track new issues
    psts baseline create
    psts baseline compare
    
    # Preview and apply security fixes
    psts fix preview
    psts fix apply --confidence 0.8
    
    # Install local validation
    psts install-hooks
    
    # Validate configuration
    psts config validate
    
    # Run in interactive mode
    psts interactive

DOCUMENTATION:
    https://github.com/J-Ellette/PowerShield
    https://github.com/J-Ellette/PowerShield/blob/main/docs/

"@ -ForegroundColor White
}

#endregion

#region Main Execution

# Parse arguments
$params = @{}
$subCommand = $null

for ($i = 0; $i -lt $Arguments.Count; $i++) {
    $arg = $Arguments[$i]
    
    if ($arg -match '^--') {
        # Long option
        $optionName = $arg -replace '^--', ''
        
        switch ($optionName) {
            'format' {
                $params['Format'] = $Arguments[++$i]
            }
            'output' {
                $params['Output'] = $Arguments[++$i]
            }
            'baseline' {
                if ($i + 1 -lt $Arguments.Count -and $Arguments[$i + 1] -notmatch '^--') {
                    $params['Baseline'] = $Arguments[++$i]
                } else {
                    $params['Baseline'] = '.powershield-baseline.json'
                }
            }
            'suppressions' {
                $params['EnableSuppressions'] = $true
            }
            'confidence' {
                $params['Confidence'] = [double]$Arguments[++$i]
            }
            'violations' {
                $params['ViolationsFile'] = $Arguments[++$i]
            }
            'force' {
                $params['Force'] = $true
            }
            default {
                Write-Warning "Unknown option: --$optionName"
            }
        }
    } elseif ($arg -match '^-') {
        # Short option (for compatibility)
        $optionName = $arg -replace '^-', ''
        
        switch ($optionName) {
            'f' {
                $params['Format'] = $Arguments[++$i]
            }
            'o' {
                $params['Output'] = $Arguments[++$i]
            }
            default {
                Write-Warning "Unknown option: -$optionName"
            }
        }
    } else {
        # Positional argument
        if ($null -eq $subCommand) {
            $subCommand = $arg
        } elseif (-not $params.ContainsKey('Path')) {
            $params['Path'] = $arg
        }
    }
}

# Execute command
# If no command provided, start interactive mode
if (-not $Command) {
    Invoke-InteractiveMode
    exit 0
}

switch ($Command) {
    'analyze' {
        if ($subCommand) {
            $params['Path'] = $subCommand
        }
        Invoke-Analyze @params
    }
    
    'config' {
        if (-not $subCommand) {
            Write-Error "Config subcommand required"
            Show-Help
            exit 1
        }
        Invoke-Config -SubCommand $subCommand
    }
    
    'baseline' {
        if (-not $subCommand) {
            Write-Error "Baseline subcommand required"
            Show-Help
            exit 1
        }
        $params['SubCommand'] = $subCommand
        Invoke-Baseline @params
    }
    
    'fix' {
        if (-not $subCommand) {
            Write-Error "Fix subcommand required"
            Show-Help
            exit 1
        }
        $params['SubCommand'] = $subCommand
        Invoke-Fix @params
    }
    
    'install-hooks' {
        Install-Hooks @params
    }
    
    'interactive' {
        Invoke-InteractiveMode
    }
    
    'version' {
        Show-Version
    }
    
    'help' {
        Show-Help
    }
    
    default {
        Write-Error "Unknown command: $Command"
        Show-Help
        exit 1
    }
}

#endregion
