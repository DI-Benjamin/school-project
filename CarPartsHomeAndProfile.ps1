#Requires -Version 5.1
#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Creates home folders + roaming profile paths for existing AD users (car parts company).
.DESCRIPTION
    - Enumerates enabled users under OU=Departments,OU=<Company>,<domain>.
    - Creates/validates a Home share and a Profiles share with correct ROOT NTFS perms
      (SYSTEM/Admins Full, Authenticated Users traverse+create this-folder-only, CREATOR OWNER
      on subfolders) plus Access-Based Enumeration.
    - HOME: pre-creates \\<srv>\Home$\<sam>, locks NTFS to the user (Modify) + SYSTEM/Admins,
      sets HomeDrive + HomeDirectory.
    - PROFILE: sets ProfilePath = \\<srv>\Profiles$\<sam>. Windows 10/11 appends ".V6"
      automatically. Optionally pre-creates "<sam>.V6" owned by the user (default on).
    - Idempotent, -WhatIf aware, continues past per-user errors.
.EXAMPLE
    .\Set-CarPartsHomeAndProfile.ps1 -FileServer FS01 -HomeRootPath D:\Shares\Home -ProfileRootPath D:\Shares\Profiles -WhatIf
.EXAMPLE
    .\Set-CarPartsHomeAndProfile.ps1 -CompanyName AcmeAutoParts -FileServer FS01 `
        -HomeRootPath D:\Shares\Home -ProfileRootPath D:\Shares\Profiles -Department Warehouse
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [string]$CompanyName            = 'CarParts',                 # <-- match your earlier run
    [string]$FileServer             = $env:COMPUTERNAME,          # server hosting the shares
    [string]$HomeShareName          = 'Home$',
    [string]$ProfileShareName       = 'Profiles$',
    [string]$HomeRootPath           = 'C:\Shares\Home',           # LOCAL path on the file server
    [string]$ProfileRootPath        = 'C:\Shares\Profiles',       # LOCAL path on the file server
    [ValidatePattern('^[A-Za-z]:$')]
    [string]$HomeDrive              = 'H:',
    [string]$Department,                                          # optional: limit to one dept
    [switch]$IncludeDisabled,
    [bool]  $PreCreateProfileFolders = $true,                     # create <sam>.V6 now
    [bool]  $CreateSharesIfMissing   = $true,
    [string]$LogDirectory            = '.'
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- logging
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$logPath   = Join-Path $LogDirectory "AD-HomeProfile_$timestamp.log"
Start-Transcript -Path $logPath -Append | Out-Null

# ---------------------------------------------------------------- module + domain
try { Import-Module ActiveDirectory -ErrorAction Stop }
catch { Write-Error "ActiveDirectory module not found. Install RSAT-AD-PowerShell or run on a DC."; Stop-Transcript | Out-Null; return }

try { $domain = Get-ADDomain; $domainDN = $domain.DistinguishedName }
catch { Write-Error "Could not contact a domain controller. $_"; Stop-Transcript | Out-Null; return }

$rootOU  = "OU=$CompanyName,$domainDN"
$deptsOU = "OU=Departments,$rootOU"
try { Get-ADOrganizationalUnit -Identity $deptsOU -ErrorAction Stop | Out-Null }
catch { Write-Error "Departments OU '$deptsOU' not found. Check -CompanyName."; Stop-Transcript | Out-Null; return }

Write-Host "Domain      : $($domain.DNSRoot)"        -ForegroundColor Cyan
Write-Host "File server : $FileServer"               -ForegroundColor Cyan
Write-Host "Home share  : \\$FileServer\$HomeShareName ($HomeRootPath)"     -ForegroundColor Cyan
Write-Host "Profile shr : \\$FileServer\$ProfileShareName ($ProfileRootPath)" -ForegroundColor Cyan

if ($FileServer -ne $env:COMPUTERNAME -and $FileServer -ne "$env:COMPUTERNAME.$($domain.DNSRoot)") {
    Write-Warning "FileServer '$FileServer' != this machine '$env:COMPUTERNAME'. Folders/shares are created on the LOCAL paths of THIS machine."
    Write-Warning "Run this on the file server, or adapt to UNC admin paths / CIM sessions for a remote host."
}

$script:Stats = [ordered]@{
    SharesCreated = 0; SharesExisting = 0
    HomeCreated = 0; HomeExisting = 0; HomeAclSet = 0
    ProfileFoldersCreated = 0; ProfileFoldersExisting = 0
    ADUpdated = 0; UsersProcessed = 0; Warnings = 0
}

# ---------------------------------------------------------------- well-known SIDs
$sidSystem  = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')      # NT AUTHORITY\SYSTEM
$sidAdmins  = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')  # BUILTIN\Administrators
$sidAuthUsr = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')      # Authenticated Users
$sidCreator = New-Object System.Security.Principal.SecurityIdentifier('S-1-3-0')       # CREATOR OWNER

# ---------------------------------------------------------------- ACL helpers
function New-FsRule {
    param(
        [Parameter(Mandatory)][System.Security.Principal.IdentityReference]$Identity,
        [Parameter(Mandatory)][System.Security.AccessControl.FileSystemRights]$Rights,
        [ValidateSet('All','ThisFolderOnly','SubfilesAndFolders')][string]$Apply = 'All'
    )
    switch ($Apply) {
        'ThisFolderOnly'     { $inh = [System.Security.AccessControl.InheritanceFlags]::None;                 $prop = [System.Security.AccessControl.PropagationFlags]::None }
        'SubfilesAndFolders' { $inh = 'ContainerInherit,ObjectInherit';                                       $prop = [System.Security.AccessControl.PropagationFlags]::InheritOnly }
        default              { $inh = 'ContainerInherit,ObjectInherit';                                       $prop = [System.Security.AccessControl.PropagationFlags]::None }
    }
    New-Object System.Security.AccessControl.FileSystemAccessRule($Identity, $Rights, $inh, $prop, [System.Security.AccessControl.AccessControlType]::Allow)
}

function Set-SecureAcl {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Security.AccessControl.FileSystemAccessRule[]]$Rules,
        [System.Security.Principal.IdentityReference]$Owner   # optional
    )
    if (-not $PSCmdlet.ShouldProcess($Path, 'Apply NTFS ACL')) { return }
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)               # break inheritance, drop inherited ACEs
    @($acl.Access) | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
    foreach ($r in $Rules) { $acl.AddAccessRule($r) }
    if ($Owner) { $acl.SetOwner($Owner) }                     # requires SeRestorePrivilege (admins have it)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

# ---------------------------------------------------------------- share + root setup
function Initialize-ShareRoot {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ShareName,
        [Parameter(Mandatory)][string]$LocalPath,
        [ValidateSet('None','Manual')][string]$Caching = 'Manual'
    )
    if (-not (Test-Path -LiteralPath $LocalPath)) {
        if ($PSCmdlet.ShouldProcess($LocalPath, 'Create root folder')) {
            New-Item -ItemType Directory -Path $LocalPath -Force | Out-Null
            Write-Host "  [ +  ] Created root folder: $LocalPath" -ForegroundColor Green
        }
    } else { Write-Host "  [skip] Root folder exists: $LocalPath" -ForegroundColor DarkGray }

    # Root ACL: admins/system full; authenticated users may traverse + create their own folder;
    # CREATOR OWNER full on anything created beneath (covers OS-created profile folders).
    $rootRules = @(
        New-FsRule -Identity $sidSystem  -Rights FullControl                      -Apply All
        New-FsRule -Identity $sidAdmins  -Rights FullControl                      -Apply All
        New-FsRule -Identity $sidAuthUsr -Rights 'ReadAndExecute,CreateDirectories' -Apply ThisFolderOnly
        New-FsRule -Identity $sidCreator -Rights FullControl                      -Apply SubfilesAndFolders
    )
    Set-SecureAcl -Path $LocalPath -Rules $rootRules

    $existing = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  [skip] Share exists: $ShareName" -ForegroundColor DarkGray
        $script:Stats.SharesExisting++
        if ($PSCmdlet.ShouldProcess($ShareName, 'Reconcile share access + ABE')) {
            try { Grant-SmbShareAccess -Name $ShareName -AccountName 'Authenticated Users' -AccessRight Full -Force -ErrorAction Stop | Out-Null } catch {}
            try { Revoke-SmbShareAccess -Name $ShareName -AccountName 'Everyone' -Force -ErrorAction Stop | Out-Null } catch {}
            try { Set-SmbShare -Name $ShareName -FolderEnumerationMode AccessBased -Force -ErrorAction Stop } catch {}
        }
    }
    elseif ($CreateSharesIfMissing) {
        if ($PSCmdlet.ShouldProcess("\\$FileServer\$ShareName -> $LocalPath", 'Create SMB share')) {
            New-SmbShare -Name $ShareName -Path $LocalPath -FullAccess 'Authenticated Users' `
                         -FolderEnumerationMode AccessBased -CachingMode $Caching -ErrorAction Stop | Out-Null
            Write-Host "  [ +  ] Created share: \\$FileServer\$ShareName" -ForegroundColor Green
            $script:Stats.SharesCreated++
        }
    }
    else { Write-Warning "Share '$ShareName' missing and -CreateSharesIfMissing is `$false." ; $script:Stats.Warnings++ }
}

Write-Host "`n=== Setting up shares ===" -ForegroundColor Cyan
Initialize-ShareRoot -ShareName $HomeShareName    -LocalPath $HomeRootPath    -Caching Manual   # home dirs cacheable
Initialize-ShareRoot -ShareName $ProfileShareName -LocalPath $ProfileRootPath -Caching None     # MS: no offline files on profiles

# ---------------------------------------------------------------- per-user provisioning
Write-Host "`n=== Provisioning users ===" -ForegroundColor Cyan
$filter = if ($IncludeDisabled) { '*' } else { 'Enabled -eq $true' }
$searchBase = if ($Department) { "OU=Users,OU=$Department,$deptsOU" } else { $deptsOU }
try { Get-ADOrganizationalUnit -Identity $searchBase -ErrorAction Stop | Out-Null }
catch { Write-Error "Search base '$searchBase' not found."; Stop-Transcript | Out-Null; return }

$users = Get-ADUser -SearchBase $searchBase -Filter $filter -SearchScope Subtree `
                    -Properties SID, HomeDirectory, HomeDrive, ProfilePath

if (-not $users) { Write-Warning "No users found under $searchBase." }

foreach ($u in $users) {
    $sam = $u.SamAccountName
    try {
        $script:Stats.UsersProcessed++
        $homeUnc    = "\\$FileServer\$HomeShareName\$sam"
        $profileUnc = "\\$FileServer\$ProfileShareName\$sam"           # OS appends .V6
        $homeLocal  = Join-Path $HomeRootPath    $sam
        $userSid    = New-Object System.Security.Principal.SecurityIdentifier($u.SID.Value)

        Write-Host ("`n[{0}]" -f $sam) -ForegroundColor White

        # ---- HOME folder (pre-create + lock down) ----
        if (Test-Path -LiteralPath $homeLocal) {
            Write-Host "  [skip] Home exists: $homeLocal" -ForegroundColor DarkGray
            $script:Stats.HomeExisting++
        } else {
            if ($PSCmdlet.ShouldProcess($homeLocal, 'Create home folder')) {
                New-Item -ItemType Directory -Path $homeLocal -Force | Out-Null
                Write-Host "  [ +  ] Created home: $homeLocal" -ForegroundColor Green
                $script:Stats.HomeCreated++
            }
        }
        # NTFS: user = Modify (cannot re-ACL/own); SYSTEM + Admins = Full. Owner left as Administrators.
        if (Test-Path -LiteralPath $homeLocal) {
            $homeRules = @(
                New-FsRule -Identity $sidSystem -Rights FullControl -Apply All
                New-FsRule -Identity $sidAdmins -Rights FullControl -Apply All
                New-FsRule -Identity $userSid   -Rights Modify      -Apply All
            )
            Set-SecureAcl -Path $homeLocal -Rules $homeRules
            $script:Stats.HomeAclSet++
        }

        # ---- ROAMING PROFILE folder (optional pre-create of <sam>.V6, owned by user) ----
        if ($PreCreateProfileFolders) {
            $profileV6 = Join-Path $ProfileRootPath "$sam.V6"
            if (Test-Path -LiteralPath $profileV6) {
                Write-Host "  [skip] Profile folder exists: $profileV6" -ForegroundColor DarkGray
                $script:Stats.ProfileFoldersExisting++
            } else {
                if ($PSCmdlet.ShouldProcess($profileV6, 'Create profile folder (.V6)')) {
                    New-Item -ItemType Directory -Path $profileV6 -Force | Out-Null
                    Write-Host "  [ +  ] Created profile folder: $profileV6" -ForegroundColor Green
                    $script:Stats.ProfileFoldersCreated++
                }
            }
            if (Test-Path -LiteralPath $profileV6) {
                # User must have Full Control AND be the owner or Windows refuses to load the profile.
                $profRules = @(
                    New-FsRule -Identity $sidSystem -Rights FullControl -Apply All
                    New-FsRule -Identity $sidAdmins -Rights FullControl -Apply All
                    New-FsRule -Identity $userSid   -Rights FullControl -Apply All
                )
                Set-SecureAcl -Path $profileV6 -Rules $profRules -Owner $userSid
            }
        }

        # ---- AD attributes (always set -> self-healing) ----
        if ($PSCmdlet.ShouldProcess($sam, "Set HomeDrive=$HomeDrive, HomeDirectory, ProfilePath")) {
            Set-ADUser -Identity $sam -HomeDrive $HomeDrive -HomeDirectory $homeUnc -ProfilePath $profileUnc -ErrorAction Stop
            Write-Host "  [ ad ] HomeDrive=$HomeDrive  Home=$homeUnc  Profile=$profileUnc" -ForegroundColor Green
            $script:Stats.ADUpdated++
        }
    }
    catch {
        Write-Warning "User '$sam' failed: $($_.Exception.Message)"
        $script:Stats.Warnings++
    }
}

# ---------------------------------------------------------------- summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$script:Stats.GetEnumerator() | ForEach-Object { "{0,-22}: {1}" -f $_.Key, $_.Value } | Write-Host
Write-Host "Log: $logPath" -ForegroundColor Cyan
Stop-Transcript | Out-Null