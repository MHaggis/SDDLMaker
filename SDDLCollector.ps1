<#
.SYNOPSIS
    Collects SDDL (Security Descriptor Definition Language) information from Windows systems.

.DESCRIPTION
    This script collects detailed file and security information from Windows systems, including SDDL strings,
    file hashes, and system information.
#>

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrative privileges."
    Write-Warning "Please run PowerShell as Administrator and try again."
    exit
}

# Define output paths using $PSScriptRoot
$OutputPath = Join-Path $PSScriptRoot "sddl_collection.csv"
$SystemInfoPath = Join-Path $PSScriptRoot "system_info.txt"

# Collect system information
Write-Host "Collecting system information..."
systeminfo > $SystemInfoPath

# Collect file information
Write-Host "Collecting file information from C:\..."
Get-ChildItem -Recurse "C:\" -ErrorAction SilentlyContinue | 
    Where-Object { !$_.PSIsContainer } | 
    Select-Object @{N='DirectoryName';E={$_.DirectoryName}},
                 @{N='Name';E={$_.Name}},
                 @{N='FullName';E={$_.FullName}},
                 @{N='Length';E={$_.Length}},
                 @{N='CreationTimeUtc';E={(Get-Date -Format 's' $_.CreationTimeUtc).Replace('T', ' ')}},
                 @{N='LastAccessTimeUtc';E={(Get-Date -Format 's' $_.LastAccessTimeUtc).Replace('T', ' ')}},
                 @{N='LastWriteTimeUtc';E={(Get-Date -Format 's' $_.LastWriteTimeUtc).Replace('T', ' ')}},
                 @{N='Attributes';E={$_.Attributes}},
                 @{N='MD5';E={
                    try { (Get-FileHash $_.FullName -Algorithm MD5 -ErrorAction Stop).Hash }
                    catch { "Error calculating hash" }
                 }},
                 @{N='SHA1';E={
                    try { (Get-FileHash $_.FullName -Algorithm SHA1 -ErrorAction Stop).Hash }
                    catch { "Error calculating hash" }
                 }},
                 @{N='SHA256';E={
                    try { (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash }
                    catch { "Error calculating hash" }
                 }},
                 @{N='SDDL';E={
                    try { (Get-Acl $_.FullName -ErrorAction Stop).Sddl }
                    catch { "Error getting SDDL: $($_.Exception.Message)" }
                 }} |
    Export-Csv -Path $OutputPath -NoTypeInformation

Write-Host "Collection complete!"
Write-Host "File information saved to: $OutputPath"
Write-Host "System information saved to: $SystemInfoPath"

# Display summary
$fileCount = (Import-Csv $OutputPath | Measure-Object).Count
Write-Host "Total files processed: $fileCount"