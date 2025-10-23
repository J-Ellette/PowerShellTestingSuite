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
        if (-not $rulesMap.ContainsKey($violation.RuleId)) {
            $rulesMap[$violation.RuleId] = @{
                id = $violation.RuleId
                name = $violation.Name
                shortDescription = @{ text = $violation.Message }
                fullDescription = @{ text = $violation.Message }
                defaultConfiguration = @{
                    level = switch ($violation.Severity) {
                        'Critical' { 'error' }
                        'High' { 'error' }
                        'Medium' { 'warning' }
                        'Low' { 'note' }
                        default { 'warning' }
                    }
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
        $result = @{
            ruleId = $violation.RuleId
            ruleIndex = [array]::IndexOf(@($rulesMap.Keys), $violation.RuleId)
            message = @{ text = $violation.Message }
            level = switch ($violation.Severity) {
                'Critical' { 'error' }
                'High' { 'error' }
                'Medium' { 'warning' }
                'Low' { 'note' }
                default { 'warning' }
            }
            locations = @(@{
                physicalLocation = @{
                    artifactLocation = @{ 
                        uri = $violation.FilePath.Replace('\', '/').TrimStart('./')
                        uriBaseId = 'SRCROOT'
                    }
                    region = @{
                        startLine = $violation.LineNumber
                        startColumn = 1
                        snippet = @{ text = $violation.Code }
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

Export-ModuleMember -Function Convert-ToSARIF
