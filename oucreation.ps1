#Requires -Version 5.1
#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Builds an OU tree, creates AD groups, bulk-creates users, and nests groups (AGDLP).
    Tailored for a car parts company. Idempotent and -WhatIf aware.
.EXAMPLE
    .\Build-CarPartsAD.ps1 -WhatIf
.EXAMPLE
    .\Build-CarPartsAD.ps1 -CompanyName 'AcmeAutoParts' `
        -GroupCsvPath C:\AD\groups.csv -UserCsvPath C:\AD\users.csv -NestingCsvPath C:\AD\nesting.csv
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [string]$CompanyName                   = 'CarParts',        # <-- change to your company
    [string]$GroupCsvPath                  = '.\groups.csv',
    [string]$UserCsvPath                   = '.\users.csv',
    [string]$NestingCsvPath                = '.\nesting.csv',
    [string]$LogDirectory                  = '.',
    [string]$CredentialExportDirectory     = '.',
    [int]   $PasswordLength                = 16,
    [bool]  $DefaultChangeAtLogon          = $true,
    [bool]  $ProtectFromAccidentalDeletion = $true
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- logging
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$logPath   = Join-Path $LogDirectory "AD-Build_$timestamp.log"
Start-Transcript -Path $logPath -Append | Out-Null

# ---------------------------------------------------------------- module + domain
try { Import-Module ActiveDirectory -ErrorAction Stop }
catch {
    Write-Error "ActiveDirectory module not found. Install RSAT-AD-PowerShell or run on a domain controller."
    Stop-Transcript | Out-Null; return
}

try {
    $domain   = Get-ADDomain
    $domainDN = $domain.DistinguishedName
    $upnSuffix = $domain.DNSRoot
}
catch {
    Write-Error "Could not contact a domain controller / read the domain. $_"
    Stop-Transcript | Out-Null; return
}

$rootOU = "OU=$CompanyName,$domainDN"
Write-Host "Domain : $($domain.DNSRoot)" -ForegroundColor Cyan
Write-Host "Root OU: $rootOU"            -ForegroundColor Cyan

$script:Stats = [ordered]@{
    OUsCreated = 0; OUsSkipped = 0
    GroupsCreated = 0; GroupsSkipped = 0; GroupMembersAdded = 0
    UsersCreated = 0; UsersSkipped = 0; UserGroupAdds = 0
    NestingAdds = 0; Warnings = 0
}

# ---------------------------------------------------------------- helpers
function ConvertTo-BoolOrDefault {
    param($Value, [bool]$Default)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return $Default }
    switch -Regex ("$Value".Trim()) {
        '^(?i:true|yes|y|1|enabled)$'   { return $true }
        '^(?i:false|no|n|0|disabled)$'  { return $false }
        default                         { return $Default }
    }
}

function New-RandomPassword {
    param([int]$Length = 16)
    # Excludes look-alike characters. Temp password only — change required at logon.
    $sets = [ordered]@{
        Upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
        Lower   = 'abcdefghijkmnpqrstuvwxyz'
        Digit   = '23456789'
        Special = '!@#$%^&*-_=+?'
    }
    $all   = -join $sets.Values
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($s in $sets.Values) { $chars.Add($s[(Get-Random -Maximum $s.Length)]) }  # one of each class
    while ($chars.Count -lt $Length) { $chars.Add($all[(Get-Random -Maximum $all.Length)]) }
    return -join ($chars | Sort-Object { Get-Random })
}

function Get-SamFromName {
    param([string]$First, [string]$Last)
    $base = (("" + $First).Substring(0, [Math]::Min(1, ("" + $First).Length)) + ("" + $Last))
    $base = ($base -replace '[^a-zA-Z0-9]', '').ToLower()
    if ($base.Length -gt 20) { $base = $base.Substring(0, 20) }   # sAMAccountName limit
    return $base
}

function New-OUIfMissing {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ParentDN,
        [bool]$Protect = $true
    )
    $ouDN = "OU=$Name,$ParentDN"
    $exists = $false
    try { $null = Get-ADOrganizationalUnit -Identity $ouDN -ErrorAction Stop; $exists = $true } catch { $exists = $false }
    if ($exists) {
        Write-Host "  [skip] OU exists : $ouDN" -ForegroundColor DarkGray
        $script:Stats.OUsSkipped++
        return $ouDN
    }
    if ($PSCmdlet.ShouldProcess($ouDN, 'Create OU')) {
        New-ADOrganizationalUnit -Name $Name -Path $ParentDN -ProtectedFromAccidentalDeletion:$Protect -ErrorAction Stop
        Write-Host "  [ +  ] Created OU: $ouDN" -ForegroundColor Green
        $script:Stats.OUsCreated++
    }
    return $ouDN
}

function New-GroupIfMissing {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Security','Distribution')][string]$Category = 'Security',
        [ValidateSet('Global','DomainLocal','Universal')][string]$Scope = 'Global',
        [string]$Description,
        [string]$ManagedBy
    )
    $existing = $null
    try { $existing = Get-ADGroup -Identity $Name -ErrorAction Stop } catch {}
    if ($existing) {
        Write-Host "  [skip] Group exists: $Name" -ForegroundColor DarkGray
        $script:Stats.GroupsSkipped++
        return
    }
    if ($PSCmdlet.ShouldProcess("$Name in $Path", 'Create group')) {
        $params = @{
            Name = $Name; SamAccountName = $Name      # keep group names <= 20 chars
            GroupCategory = $Category; GroupScope = $Scope; Path = $Path
        }
        if ($Description) { $params.Description = $Description }
        if ($ManagedBy)   { $params.ManagedBy   = $ManagedBy }
        New-ADGroup @params -ErrorAction Stop
        Write-Host "  [ +  ] Created group: $Name ($Scope/$Category)" -ForegroundColor Green
        $script:Stats.GroupsCreated++
    }
}

function Add-MemberIfMissing {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Group,
        [Parameter(Mandatory)][string]$Member   # sAMAccountName of a user OR a group
    )
    try { $g = Get-ADGroup -Identity $Group -ErrorAction Stop }
    catch { Write-Warning "Group '$Group' not found; cannot add '$Member'."; $script:Stats.Warnings++; return 'Failed' }

    try {
        $already = $false
        Get-ADGroupMember -Identity $g -ErrorAction Stop | ForEach-Object {
            if ($_.SamAccountName -eq $Member -or $_.Name -eq $Member -or $_.DistinguishedName -eq $Member) { $already = $true }
        }
        if ($already) { return 'AlreadyMember' }
    } catch { }   # fall through (e.g. very large group) and let Add catch a duplicate

    if ($PSCmdlet.ShouldProcess("$Member -> $Group", 'Add member')) {
        try { Add-ADGroupMember -Identity $g -Members $Member -ErrorAction Stop; return 'Added' }
        catch {
            if ($_.Exception.Message -match 'already a member') { return 'AlreadyMember' }
            Write-Warning "Failed to add '$Member' to '$Group': $($_.Exception.Message)"; $script:Stats.Warnings++; return 'Failed'
        }
    }
    return 'WhatIf'
}

function New-UserIfMissing {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Sam,
        [Parameter(Mandatory)][string]$First,
        [Parameter(Mandatory)][string]$Last,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$UpnSuffix,
        [string]$Title, [string]$Email, [string]$Company, [string]$Department,
        [string]$PlainPassword,
        [bool]$Enabled = $true,
        [bool]$ChangeAtLogon = $true,
        [int]$PwLength = 16
    )
    $existing = $null
    try { $existing = Get-ADUser -Identity $Sam -ErrorAction Stop } catch {}
    if ($existing) {
        Write-Host "  [skip] User exists: $Sam" -ForegroundColor DarkGray
        $script:Stats.UsersSkipped++
        return [pscustomobject]@{ Status = 'Exists'; Sam = $Sam; Password = $null }
    }

    $generated = $false
    if ([string]::IsNullOrWhiteSpace($PlainPassword)) { $PlainPassword = New-RandomPassword -Length $PwLength; $generated = $true }
    $secure   = ConvertTo-SecureString $PlainPassword -AsPlainText -Force
    $display  = "$First $Last".Trim()

    if ($PSCmdlet.ShouldProcess("$display ($Sam) in $Path", 'Create user')) {
        $params = @{
            Name = $display; DisplayName = $display
            GivenName = $First; Surname = $Last
            SamAccountName = $Sam; UserPrincipalName = "$Sam@$UpnSuffix"
            AccountPassword = $secure; Enabled = $Enabled
            ChangePasswordAtLogon = $ChangeAtLogon; Path = $Path
        }
        if ($Title)      { $params.Title       = $Title }
        if ($Department) { $params.Department   = $Department }
        if ($Company)    { $params.Company      = $Company }
        if ($Email)      { $params.EmailAddress = $Email }
        try {
            New-ADUser @params -ErrorAction Stop
            Write-Host "  [ +  ] Created user: $display ($Sam)" -ForegroundColor Green
            $script:Stats.UsersCreated++
            return [pscustomobject]@{ Status = 'Created'; Sam = $Sam; Password = ($(if ($generated) { $PlainPassword } else { $null })) }
        }
        catch {
            Write-Warning "Failed to create user '$Sam': $($_.Exception.Message)"; $script:Stats.Warnings++
            return [pscustomobject]@{ Status = 'Failed'; Sam = $Sam; Password = $null }
        }
    }
    return [pscustomobject]@{ Status = 'WhatIf'; Sam = $Sam; Password = $null }
}

# ---------------------------------------------------------------- OU structure
$departments = @(
    'Sales','Ecommerce','Procurement','Warehouse','Logistics','Workshop',
    'CustomerService','Finance','HR','IT','Marketing','Management'
)

Write-Host "`n=== Building OU structure ===" -ForegroundColor Cyan
$P = $ProtectFromAccidentalDeletion

New-OUIfMissing -Name $CompanyName       -ParentDN $domainDN -Protect $P | Out-Null
$deptParent  = New-OUIfMissing -Name 'Departments'     -ParentDN $rootOU      -Protect $P
New-OUIfMissing -Name 'Groups'           -ParentDN $rootOU      -Protect $P | Out-Null
New-OUIfMissing -Name 'ServiceAccounts'  -ParentDN $rootOU      -Protect $P | Out-Null
New-OUIfMissing -Name 'Servers'          -ParentDN $rootOU      -Protect $P | Out-Null
$computersOU = New-OUIfMissing -Name 'Computers'       -ParentDN $rootOU      -Protect $P
New-OUIfMissing -Name 'Workstations'     -ParentDN $computersOU -Protect $P | Out-Null
New-OUIfMissing -Name 'Laptops'          -ParentDN $computersOU -Protect $P | Out-Null
$disabledOU  = New-OUIfMissing -Name 'DisabledObjects' -ParentDN $rootOU      -Protect $P
New-OUIfMissing -Name 'Users'            -ParentDN $disabledOU  -Protect $P | Out-Null
New-OUIfMissing -Name 'Computers'        -ParentDN $disabledOU  -Protect $P | Out-Null

foreach ($d in $departments) {
    $deptDN = New-OUIfMissing -Name $d -ParentDN $deptParent -Protect $P
    New-OUIfMissing -Name 'Users'     -ParentDN $deptDN -Protect $P | Out-Null
    New-OUIfMissing -Name 'Groups'    -ParentDN $deptDN -Protect $P | Out-Null
    New-OUIfMissing -Name 'Computers' -ParentDN $deptDN -Protect $P | Out-Null
}

# ---------------------------------------------------------------- groups from CSV
Write-Host "`n=== Creating groups from CSV ===" -ForegroundColor Cyan
if (-not (Test-Path $GroupCsvPath)) {
    Write-Warning "Group CSV not found at '$GroupCsvPath'. Skipping group creation."
}
else {
    foreach ($row in (Import-Csv -Path $GroupCsvPath)) {
        try {
            if ([string]::IsNullOrWhiteSpace($row.Name)) { continue }
            $parent = ("" + $row.ParentOU).Trim()
            if     ([string]::IsNullOrWhiteSpace($parent)) { $parentDN = "OU=Groups,$rootOU" }
            elseif ($parent -match '^(?i)OU=')             { $parentDN = "$parent,$domainDN" }
            else                                           { $parentDN = "OU=Groups,OU=$parent,OU=Departments,$rootOU" }

            try { Get-ADOrganizationalUnit -Identity $parentDN -ErrorAction Stop | Out-Null }
            catch { Write-Warning "Parent OU '$parentDN' for group '$($row.Name)' not found. Skipping."; $script:Stats.Warnings++; continue }

            $scope    = if ($row.GroupScope)    { $row.GroupScope }    else { 'Global' }
            $category = if ($row.GroupCategory) { $row.GroupCategory } else { 'Security' }
            New-GroupIfMissing -Name $row.Name -Path $parentDN -Category $category `
                               -Scope $scope -Description $row.Description -ManagedBy $row.ManagedBy

            if ($row.PSObject.Properties.Name -contains 'Members' -and $row.Members) {
                $row.Members -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object {
                    if ((Add-MemberIfMissing -Group $row.Name -Member $_) -eq 'Added') {
                        Write-Host "      member added: $_" -ForegroundColor Green; $script:Stats.GroupMembersAdded++
                    }
                }
            }
        }
        catch { Write-Warning "Row for group '$($row.Name)' failed: $($_.Exception.Message)"; $script:Stats.Warnings++ }
    }
}

# ---------------------------------------------------------------- group nesting (AGDLP)
Write-Host "`n=== Nesting groups (GG -> DL) ===" -ForegroundColor Cyan
if (-not (Test-Path $NestingCsvPath)) {
    Write-Warning "Nesting CSV not found at '$NestingCsvPath'. Skipping nesting."
}
else {
    foreach ($row in (Import-Csv -Path $NestingCsvPath)) {
        if ([string]::IsNullOrWhiteSpace($row.MemberGroup) -or [string]::IsNullOrWhiteSpace($row.IntoGroup)) { continue }
        $member = $row.MemberGroup.Trim(); $into = $row.IntoGroup.Trim()
        $result = Add-MemberIfMissing -Group $into -Member $member
        if     ($result -eq 'Added')         { Write-Host "  [ +  ] $member -> $into" -ForegroundColor Green; $script:Stats.NestingAdds++ }
        elseif ($result -eq 'AlreadyMember') { Write-Host "  [skip] $member already in $into" -ForegroundColor DarkGray }
    }
}

# ---------------------------------------------------------------- users from CSV
Write-Host "`n=== Creating users from CSV ===" -ForegroundColor Cyan
$createdCreds = New-Object System.Collections.Generic.List[object]

if (-not (Test-Path $UserCsvPath)) {
    Write-Warning "User CSV not found at '$UserCsvPath'. Skipping user creation."
}
else {
    foreach ($row in (Import-Csv -Path $UserCsvPath)) {
        try {
            if ([string]::IsNullOrWhiteSpace($row.FirstName) -or [string]::IsNullOrWhiteSpace($row.LastName)) {
                Write-Warning "Skipping row with missing FirstName/LastName."; $script:Stats.Warnings++; continue
            }
            $dept = ("" + $row.Department).Trim()
            if ($departments -notcontains $dept) {
                Write-Warning "Department '$dept' for $($row.FirstName) $($row.LastName) is not a known OU. Skipping."; $script:Stats.Warnings++; continue
            }

            $usersOU = "OU=Users,OU=$dept,OU=Departments,$rootOU"
            try { Get-ADOrganizationalUnit -Identity $usersOU -ErrorAction Stop | Out-Null }
            catch { Write-Warning "Users OU '$usersOU' not found. Skipping $($row.FirstName) $($row.LastName)."; $script:Stats.Warnings++; continue }

            $sam = if ($row.SamAccountName) { $row.SamAccountName.Trim() } else { Get-SamFromName -First $row.FirstName -Last $row.LastName }
            if ([string]::IsNullOrWhiteSpace($sam)) { Write-Warning "Could not derive a sAMAccountName for $($row.FirstName) $($row.LastName)."; $script:Stats.Warnings++; continue }

            $enabled = ConvertTo-BoolOrDefault -Value $row.Enabled      -Default $true
            $change  = ConvertTo-BoolOrDefault -Value $row.ChangeAtLogon -Default $DefaultChangeAtLogon

            $res = New-UserIfMissing -Sam $sam -First $row.FirstName -Last $row.LastName -Path $usersOU `
                       -UpnSuffix $upnSuffix -Title $row.Title -Email $row.Email -Company $CompanyName `
                       -Department $dept -PlainPassword $row.Password -Enabled $enabled `
                       -ChangeAtLogon $change -PwLength $PasswordLength

            if ($res.Status -eq 'Created' -and $res.Password) {
                $createdCreds.Add([pscustomobject]@{
                    SamAccountName = $res.Sam; Name = "$($row.FirstName) $($row.LastName)"
                    UserPrincipalName = "$($res.Sam)@$upnSuffix"; Department = $dept; TempPassword = $res.Password
                })
            }

            # always reconcile membership (created OR pre-existing) -> self-healing
            $ggName = "GG-$dept"
            if ((Add-MemberIfMissing -Group $ggName -Member $sam) -eq 'Added') {
                Write-Host "      added to $ggName" -ForegroundColor Green; $script:Stats.UserGroupAdds++
            }

            # optional extra groups (semicolon/comma separated)
            if ($row.PSObject.Properties.Name -contains 'AdditionalGroups' -and $row.AdditionalGroups) {
                $row.AdditionalGroups -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object {
                    if ((Add-MemberIfMissing -Group $_ -Member $sam) -eq 'Added') {
                        Write-Host "      added to $_" -ForegroundColor Green; $script:Stats.UserGroupAdds++
                    }
                }
            }
        }
        catch { Write-Warning "User row '$($row.FirstName) $($row.LastName)' failed: $($_.Exception.Message)"; $script:Stats.Warnings++ }
    }
}

# ---------------------------------------------------------------- export generated credentials
if ($createdCreds.Count -gt 0) {
    $credPath = Join-Path $CredentialExportDirectory "NewUserCredentials_$timestamp.csv"
    $createdCreds | Export-Csv -Path $credPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n*** $($createdCreds.Count) temporary password(s) written to: $credPath ***" -ForegroundColor Yellow
    Write-Host "*** This file contains plaintext temp passwords. Distribute securely, then DELETE it. ***" -ForegroundColor Yellow
    Write-Host "*** All accounts require a password change at first logon. ***" -ForegroundColor Yellow
}

# ---------------------------------------------------------------- summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$script:Stats.GetEnumerator() | ForEach-Object { "{0,-18}: {1}" -f $_.Key, $_.Value } | Write-Host
Write-Host "Log: $logPath" -ForegroundColor Cyan
Stop-Transcript | Out-Null