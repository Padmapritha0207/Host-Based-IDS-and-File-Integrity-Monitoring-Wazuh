<#
.SYNOPSIS
    Wazuh Active Response script for Windows: Automated File Quarantine
    Triggered when suspicious scripts or web shells are detected on Windows endpoints.
#>

param(
    [string]$TargetFile,
    [string]$RuleId = "100011"
)

$QuarantineDir = "C:\ProgramData\Wazuh-Quarantine"
$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# If input came via standard input pipeline from Wazuh
if (-not $TargetFile) {
    $inputLine = [Console]::In.ReadLine()
    if ($inputLine -match '"path"\s*:\s*"([^"]+)"') {
        $TargetFile = $matches[1]
    }
}

if (-not (Test-Path $QuarantineDir)) {
    New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
    # Restrict ACLs to SYSTEM and Administrators only
    $acl = Get-Acl $QuarantineDir
    $acl.SetAccessRuleProtection($true, $false)
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $acl.AddAccessRule($systemRule)
    $acl.AddAccessRule($adminRule)
    Set-Acl -Path $QuarantineDir -AclObject $acl
}

if ($TargetFile -and (Test-Path $TargetFile)) {
    $hash = (Get-FileHash -Path $TargetFile -Algorithm SHA256).Hash
    $baseName = [System.IO.Path]::GetFileName($TargetFile)
    $destination = Join-Path $QuarantineDir "$($baseName)_$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()).quarantine"

    Move-Item -Path $TargetFile -Destination $destination -Force
    # Strip permissions
    $fileAcl = Get-Acl $destination
    $fileAcl.SetAccessRuleProtection($true, $false)
    Set-Acl -Path $destination -AclObject $fileAcl

    $logEntry = "$Timestamp [quarantine_file.ps1] QUARANTINED: '$TargetFile' -> '$destination' | SHA256: $hash | Rule: $RuleId"
    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
    Write-Output "File successfully quarantined to $destination"
} else {
    $logEntry = "$Timestamp [quarantine_file.ps1] WARNING: Target file not found: $TargetFile"
    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
}
