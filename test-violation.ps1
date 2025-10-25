# Test script with security violation
$password = ConvertTo-SecureString "Password123" -AsPlainText -Force
Write-Host "Testing"
