# Clean script with no violations
$hash = Get-FileHash -Path "file.txt" -Algorithm SHA256
Write-Host "Hash computed successfully: $hash"
