# Test script with insecure hash algorithm violations

# Violation 1: Using MD5 with Get-FileHash
$fileHash = Get-FileHash -Path "C:\temp\file.txt" -Algorithm MD5

# Violation 2: Using SHA1 with Get-FileHash
$anotherHash = Get-FileHash -Path "C:\temp\another.txt" -Algorithm SHA1

# Violation 3: Using MD5 .NET class directly
$md5 = [System.Security.Cryptography.MD5]::Create()
$hashBytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("test"))

# Violation 4: SHA1 crypto service provider
$sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
$sha1Hash = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("data"))

# Correct usage (should not trigger violation)
$secureHash = Get-FileHash -Path "C:\temp\file.txt" -Algorithm SHA256
