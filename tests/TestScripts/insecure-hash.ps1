# Test script demonstrating secure hash algorithm usage

# Secure usage: Using SHA256 with Get-FileHash (default and recommended)
$fileHash = Get-FileHash -Path "C:\temp\file.txt" -Algorithm SHA256

# Secure usage: Using SHA256 explicitly
$anotherHash = Get-FileHash -Path "C:\temp\another.txt" -Algorithm SHA256

# Secure usage: Using SHA256 .NET class directly
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("test"))

# Secure usage: SHA256 crypto service provider
$sha256Provider = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
$sha256Hash = $sha256Provider.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("data"))

# Secure usage: Using SHA512 for even stronger hashing
$secureHash = Get-FileHash -Path "C:\temp\file.txt" -Algorithm SHA512
