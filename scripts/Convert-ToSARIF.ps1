<#
.SYNOPSIS
    Converts PSTS results to SARIF format for GitHub Security tab integration.
.DESCRIPTION
    Converts PowerShell Security Analyzer JSON results to SARIF 2.1.0 format.
.PARAMETER InputFile
    Path to the PSTS JSON results file
.PARAMETER OutputFile
    Path where the SARIF file should be written
.EXAMPLE
    Convert-ToSARIF -InputFile results.json -OutputFile results.sarif
#>

function Convert-ToSARIF {
    param(
        [Parameter(Mandatory)]
        [string]$InputFile,
        
        [Parameter(Mandatory)]
        [string]$OutputFile
    )

    if (-not (Test-Path $InputFile)) {
        throw "Input file not found: $InputFile"
    }

    $results = Get-Content $InputFile -Raw | ConvertFrom-Json
    
    # Initialize SARIF structure
    $sarif = @{
        '$schema' = 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json'
        version = '2.1.0'
        runs = @(@{
            tool = @{
                driver = @{
                    name = 'PSTS (PowerShell Testing Suite)'
                    version = $results.metadata.version
                    informationUri = 'https://github.com/J-Ellette/PowerShellTestingSuite'
                    semanticVersion = $results.metadata.version
                    rules = @()
                }
            }
            results = @()
            originalUriBaseIds = @{
                SRCROOT = @{
                    uri = 'file:///'
                }
            }
        })
    }

    # Build rules dictionary
    $rulesMap = @{}
    foreach ($violation in $results.violations) {
        if ($violation -and $violation.RuleId -and -not $rulesMap.ContainsKey($violation.RuleId)) {
            $severityLevel = if ($violation.Severity) {
                switch ($violation.Severity) {
                    'Critical' { 'error' }
                    'High' { 'error' }
                    'Medium' { 'warning' }
                    'Low' { 'note' }
                    default { 'warning' }
                }
            } else {
                'warning'
            }
            
            $rulesMap[$violation.RuleId] = @{
                id = $violation.RuleId
                name = if ($violation.Name) { $violation.Name } else { $violation.RuleId }
                shortDescription = @{ text = if ($violation.Message) { $violation.Message } else { "Security violation" } }
                fullDescription = @{ text = if ($violation.Message) { $violation.Message } else { "Security violation detected" } }
                defaultConfiguration = @{
                    level = $severityLevel
                }
                properties = @{
                    category = 'security'
                    tags = @('security', 'powershell')
                }
            }
        }
    }

    $sarif.runs[0].tool.driver.rules = @($rulesMap.Values)

    # Build results
    foreach ($violation in $results.violations) {
        if (-not $violation -or -not $violation.RuleId -or -not $violation.LineNumber) {
            continue
        }
        
        $severityLevel = if ($violation.Severity) {
            switch ($violation.Severity) {
                'Critical' { 'error' }
                'High' { 'error' }
                'Medium' { 'warning' }
                'Low' { 'note' }
                default { 'warning' }
            }
        } else {
            'warning'
        }
        
        # Convert file path to relative URI
        $relativeUri = 'unknown'
        if ($violation.FilePath) {
            $filePath = $violation.FilePath.Replace('\', '/')
            
            # If path is absolute, convert to relative to current directory
            if ([System.IO.Path]::IsPathRooted($violation.FilePath)) {
                try {
                    $currentDir = (Get-Location).Path.Replace('\', '/')
                    if ($filePath.StartsWith($currentDir)) {
                        $relativeUri = $filePath.Substring($currentDir.Length).TrimStart('/')
                    } else {
                        # Path is absolute but not under current directory, use as-is
                        $relativeUri = $filePath
                    }
                } catch {
                    # Fallback to original path
                    $relativeUri = $filePath
                }
            } else {
                # Already relative, just clean it up
                $relativeUri = $filePath.TrimStart('./')
            }
        }
        
        $result = @{
            ruleId = $violation.RuleId
            ruleIndex = [array]::IndexOf(@($rulesMap.Keys), $violation.RuleId)
            message = @{ text = if ($violation.Message) { $violation.Message } else { "Security violation" } }
            level = $severityLevel
            locations = @(@{
                physicalLocation = @{
                    artifactLocation = @{ 
                        uri = $relativeUri
                        uriBaseId = 'SRCROOT'
                    }
                    region = @{
                        startLine = $violation.LineNumber
                        startColumn = 1
                        snippet = @{ text = if ($violation.Code) { $violation.Code } else { '' } }
                    }
                }
            })
            partialFingerprints = @{
                primaryLocationLineHash = (Get-StringHash "$($violation.FilePath):$($violation.LineNumber)")
            }
        }
        
        $sarif.runs[0].results += $result
    }

    # Write SARIF output
    $sarif | ConvertTo-Json -Depth 20 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "SARIF output written to: $OutputFile"
}

function Get-StringHash {
    param([string]$String)
    
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))
    return [System.BitConverter]::ToString($hash).Replace('-', '').Substring(0, 16)
}

if ($MyInvocation.PSScriptRoot -eq $null -or $MyInvocation.InvocationName -eq '.') {
    # Do not call Export-ModuleMember when dot-sourced
} else {
    Export-ModuleMember -Function Convert-ToSARIF  # or Generate-SecurityReport
}
