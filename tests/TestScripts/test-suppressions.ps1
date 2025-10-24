# Test script with suppression comments
# This demonstrates the suppression feature

Write-Host "Testing PSTS suppression system"

# Example 1: PSTS-SUPPRESS-NEXT with justification
# PSTS-SUPPRESS-NEXT: InsecureHashAlgorithms - Legacy system requirement for MD5 compatibility
$hash1 = Get-FileHash -Path "test.txt" -Algorithm MD5

# Example 2: Inline suppression
$password = "test123" # PSTS-SUPPRESS: CredentialExposure - Test credential for unit tests

# Example 3: Suppression with expiry date
# PSTS-SUPPRESS-NEXT: InsecureHashAlgorithms - Temporary until migration complete (2025-12-31)
$hash2 = Get-FileHash -Path "file.txt" -Algorithm SHA1

# Example 4: Block suppression
# PSTS-SUPPRESS-START: CommandInjection - Validated input only from trusted admin console
$commands = @(
    "Get-Process",
    "Get-Service"
)
foreach ($cmd in $commands) {
    Invoke-Expression $cmd
}
# PSTS-SUPPRESS-END

# Example 5: Expired suppression (should still trigger warning)
# PSTS-SUPPRESS-NEXT: CertificateValidation - Dev environment only (2024-01-01)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Example 6: Violation without suppression (should be detected)
$unsuppressedHash = Get-FileHash -Path "data.bin" -Algorithm MD5

Write-Host "Test script completed"
