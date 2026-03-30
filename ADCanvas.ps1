<#
================================================================================
  ADCanvas -- Paint the Full Picture of Your Active Directory
  Version: 2.0
  Author : Santhosh Sivarajan, Microsoft MVP
  Email  : santhosh@sivarajan.com
  Purpose: Generates a comprehensive per-domain HTML report of an entire
           Active Directory forest including all domains, DCs, users,
           computers, groups, GPOs, service accounts, trusts, and more.
  License: MIT -- Free to use, modify, and distribute.
  GitHub : https://github.com/SanthoshSivarajan/ADCanvas
================================================================================
#>

#Requires -Modules ActiveDirectory

$ReportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
$OutputFile = "$PSScriptRoot\ADCanvas_$ReportDate.html"

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   ADCanvas -- Active Directory Documentation Tool v2.0     |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   Author : Santhosh Sivarajan, Microsoft MVP              |" -ForegroundColor Cyan
Write-Host "  |   Email  : santhosh@sivarajan.com                         |" -ForegroundColor Cyan
Write-Host "  |   Web    : https://github.com/SanthoshSivarajan/ADCanvas           |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host "  [*] Target Domain : $((Get-ADDomain).DNSRoot)" -ForegroundColor White
Write-Host "  [*] Running As    : $($env:USERDOMAIN)\$($env:USERNAME)" -ForegroundColor White
Write-Host "  [*] Timestamp     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ""
Write-Host "  Collecting Active Directory data ..." -ForegroundColor Yellow
Write-Host ""

Add-Type -AssemblyName System.Web
function HtmlEncode($s) { if ($null -eq $s) { return "--" }; return [System.Web.HttpUtility]::HtmlEncode([string]$s) }
function ConvertTo-HtmlTable {
    param([Parameter(Mandatory)]$Data,[string[]]$Properties)
    if (-not $Data -or @($Data).Count -eq 0) { return '<p class="empty-note">No data found.</p>' }
    $rows = @($Data)
    if (-not $Properties) { $Properties = ($rows[0].PSObject.Properties).Name }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<div class="table-wrap"><table><thead><tr>')
    foreach ($p in $Properties) { [void]$sb.Append("<th>$(HtmlEncode $p)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $rows) {
        [void]$sb.Append('<tr>')
        foreach ($p in $Properties) {
            $val = $row.$p
            if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) { $val = ($val | ForEach-Object { [string]$_ }) -join ", " }
            [void]$sb.Append("<td>$(HtmlEncode $val)</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

# ==============================================================================
# FOREST-LEVEL COLLECTION
# ==============================================================================
try {
    $Forest          = Get-ADForest
    $ForestMode      = $Forest.ForestMode
    $ForestDomains   = $Forest.Domains
    $ForestRootDomain = $Forest.RootDomain
    $GlobalCatalogs  = $Forest.GlobalCatalogs
    $UPNSuffixes     = $Forest.UPNSuffixes
    $SPNSuffixes     = $Forest.SPNSuffixes
    $SchemaMaster    = $Forest.SchemaMaster
    $NamingMaster    = $Forest.DomainNamingMaster
    $ForestSites     = $Forest.Sites

    # Schema
    $SchemaVersionMap = @{
        13='Windows 2000'; 30='Windows Server 2003'; 31='Windows Server 2003 R2';
        44='Windows Server 2008'; 47='Windows Server 2008 R2'; 56='Windows Server 2012';
        69='Windows Server 2012 R2'; 87='Windows Server 2016'; 88='Windows Server 2019/2022';
        89='Windows Server 2022 (23H2)'; 90='Windows Server 2025'; 91='Windows Server 2025'
    }
    $SchemaDE      = Get-ADObject (Get-ADRootDSE).schemaNamingContext -Property objectVersion
    $SchemaVersion = $SchemaDE.objectVersion
    $SchemaOS      = if ($SchemaVersionMap.ContainsKey($SchemaVersion)) { $SchemaVersionMap[$SchemaVersion] } else { "Version $SchemaVersion" }

    # Domain / Forest Functional Level friendly name mapping
    $FuncLevelMap = @{
        '0'='Windows 2000'; '1'='Windows Server 2003 Interim'; '2'='Windows Server 2003';
        '3'='Windows Server 2008'; '4'='Windows Server 2008 R2'; '5'='Windows Server 2012';
        '6'='Windows Server 2012 R2'; '7'='Windows Server 2016'; '8'='Windows Server 2016';
        '9'='Windows Server 2016'; '10'='Windows Server 2025';
        'Windows2000Domain'='Windows 2000'; 'Windows2003Domain'='Windows Server 2003';
        'Windows2003InterimDomain'='Windows Server 2003 Interim';
        'Windows2008Domain'='Windows Server 2008'; 'Windows2008R2Domain'='Windows Server 2008 R2';
        'Windows2012Domain'='Windows Server 2012'; 'Windows2012R2Domain'='Windows Server 2012 R2';
        'Windows2016Domain'='Windows Server 2016'
    }
    function Get-FriendlyFuncLevel($level) {
        $s = [string]$level
        if ($FuncLevelMap.ContainsKey($s)) { return $FuncLevelMap[$s] }
        return $s
    }
    $ForestModeDisplay = Get-FriendlyFuncLevel $ForestMode

    # Tombstone & Config
    $ConfigDN       = (Get-ADRootDSE).configurationNamingContext
    $DSConfig       = Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$ConfigDN" -Properties tombstoneLifetime, garbageCollPeriod -ErrorAction SilentlyContinue
    $TombstoneLife  = if ($DSConfig.tombstoneLifetime) { $DSConfig.tombstoneLifetime } else { 60 }
    $GarbageCollect = if ($DSConfig.garbageCollPeriod) { $DSConfig.garbageCollPeriod } else { 12 }

    # SYSVOL Replication
    $PrimaryDomain  = Get-ADDomain
    $SysvolReplType = "Unknown"
    try {
        $DFSRMember = Get-ADObject -Filter 'objectClass -eq "msDFSR-Member"' -SearchBase "CN=DFSR-GlobalSettings,CN=System,$($PrimaryDomain.DistinguishedName)" -ErrorAction Stop
        if ($DFSRMember) { $SysvolReplType = "DFSR" }
    } catch { $SysvolReplType = "FRS (or DFSR not detected)" }

    # LAPS
    $LAPSDeployed = $false; $LAPSType = "Not Detected"
    try {
        $winLAPS = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter "name -eq 'ms-LAPS-Password'" -ErrorAction SilentlyContinue
        if ($winLAPS) { $LAPSDeployed = $true; $LAPSType = "Windows LAPS (Built-in)" }
        else {
            $legacyLAPS = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter "name -eq 'ms-Mcs-AdmPwd'" -ErrorAction SilentlyContinue
            if ($legacyLAPS) { $LAPSDeployed = $true; $LAPSType = "Legacy Microsoft LAPS" }
        }
    } catch { }

    # dMSA schema check (Windows Server 2025+)
    $dMSASupported = $false
    # Schema version 91+ = Windows Server 2025 which includes dMSA
    if ($SchemaVersion -ge 91) {
        $dMSASupported = $true
    } else {
        # Fallback: search for the schema class with multiple possible names
        try {
            $dMSASchema = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter {
                name -eq 'ms-DS-Delegated-Managed-Service-Account' -or
                name -eq 'ms-DS-DelegatedManagedServiceAccount' -or
                name -eq 'msDS-DelegatedManagedServiceAccount'
            } -ErrorAction SilentlyContinue
            if ($dMSASchema) { $dMSASupported = $true }
        } catch { }
        # Also try lDAPDisplayName search
        if (-not $dMSASupported) {
            try {
                $dMSASchema2 = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter "lDAPDisplayName -eq 'msDS-DelegatedManagedServiceAccount'" -ErrorAction SilentlyContinue
                if ($dMSASchema2) { $dMSASupported = $true }
            } catch { }
        }
    }

    # Optional Features
    $OptionalFeatures = Get-ADOptionalFeature -Filter * -ErrorAction SilentlyContinue | Select-Object Name, EnabledScopes, IsDisableable

    # Sites, Subnets, Site Links
    $ADSites     = Get-ADReplicationSite -Filter * | Select-Object Name, Description
    $ADSubnets   = Get-ADReplicationSubnet -Filter * | Select-Object Name, Site, Location, Description
    $ADSiteLinks = Get-ADReplicationSiteLink -Filter * | Select-Object Name, Cost, ReplicationFrequencyInMinutes, SitesIncluded
    Write-Host "  [+] Sites & Subnets collected." -ForegroundColor Green

    # Replication
    $ReplPartners = @(); $ReplFailures = @(); $ReplConnections = @()
    try {
        $ReplPartners = Get-ADReplicationPartnerMetadata -Target $($Forest.Name) -Scope Forest -ErrorAction Stop |
            Select-Object Server, Partner, PartnerType, LastReplicationAttempt, LastReplicationSuccess, LastReplicationResult, ConsecutiveReplicationFailures
        Write-Host "  [+] Replication partner metadata collected." -ForegroundColor Green
    } catch { Write-Host "  [i] Could not collect replication partner metadata." -ForegroundColor Gray }
    try {
        $ReplConnections = Get-ADReplicationConnection -Filter * -ErrorAction SilentlyContinue |
            Select-Object Name, ReplicateFromDirectoryServer, ReplicateToDirectoryServer, AutoGenerated, Enabled
        Write-Host "  [+] Replication connection objects collected." -ForegroundColor Green
    } catch { Write-Host "  [i] Could not collect replication connections." -ForegroundColor Gray }

    # Azure AD Connect / Entra Connect Detection
    $AADConnectServers = @()
    try {
        # Method 1: Look for MSOL_ service accounts (created by AAD Connect)
        $msolAccounts = Get-ADUser -Filter 'SamAccountName -like "MSOL_*"' -Properties WhenCreated, Description, Enabled -ErrorAction SilentlyContinue
        foreach ($m in $msolAccounts) {
            $serverName = ""
            if ($m.Description -match 'installed on (.+)') { $serverName = $Matches[1].Trim().TrimEnd('.') }
            $AADConnectServers += [PSCustomObject]@{
                DetectionMethod = 'MSOL Service Account'
                ServiceAccount  = $m.SamAccountName
                ServerName      = $serverName
                Enabled         = $m.Enabled
                Created         = $m.WhenCreated
                Description     = $m.Description
            }
        }
        # Method 2: Look for ADSync connector account
        $syncAccounts = Get-ADUser -Filter 'SamAccountName -like "AAD_*" -or SamAccountName -like "Sync_*"' -Properties WhenCreated, Description, Enabled -ErrorAction SilentlyContinue
        foreach ($s in $syncAccounts) {
            $serverName = ""
            if ($s.SamAccountName -match 'Sync_(.+?)_') { $serverName = $Matches[1] }
            elseif ($s.Description -match 'installed on (.+)') { $serverName = $Matches[1].Trim().TrimEnd('.') }
            $AADConnectServers += [PSCustomObject]@{
                DetectionMethod = 'Sync Service Account'
                ServiceAccount  = $s.SamAccountName
                ServerName      = $serverName
                Enabled         = $s.Enabled
                Created         = $s.WhenCreated
                Description     = $s.Description
            }
        }
        # Method 3: Check for ADSync OU or container
        $adSyncContainer = Get-ADObject -Filter 'Name -eq "ADSync" -or Name -eq "AAD Connect"' -ErrorAction SilentlyContinue
        if ($AADConnectServers.Count -gt 0) {
            Write-Host "  [+] Entra Connect / AAD Connect detected ($($AADConnectServers.Count) service account(s))." -ForegroundColor Green
        } else {
            Write-Host "  [i] No Entra Connect / AAD Connect detected." -ForegroundColor Gray
        }
    } catch {
        Write-Host "  [i] Could not check for Entra Connect." -ForegroundColor Gray
    }

    # AD Certificate Services (ADCS) Detection
    $ADCSData = @()
    try {
        $pkiContainer = Get-ADObject -SearchBase "CN=Public Key Services,CN=Services,$ConfigDN" -Filter 'objectClass -eq "pKIEnrollmentService"' -Properties dNSHostName, cACertificate, WhenCreated -ErrorAction SilentlyContinue
        foreach ($ca in $pkiContainer) {
            $ADCSData += [PSCustomObject]@{
                CAName    = $ca.Name
                Server    = $ca.dNSHostName
                Created   = $ca.WhenCreated
            }
        }
        if ($ADCSData.Count -gt 0) {
            Write-Host "  [+] AD Certificate Services detected ($($ADCSData.Count) CA(s))." -ForegroundColor Green
        } else {
            Write-Host "  [i] No AD Certificate Services (ADCS) detected." -ForegroundColor Gray
        }
    } catch { }

    # AD Recycle Bin Status
    $RecycleBinEnabled = $false
    try {
        $rbFeature = $OptionalFeatures | Where-Object { $_.Name -like "*Recycle*" }
        if ($rbFeature -and $rbFeature.EnabledScopes -and @($rbFeature.EnabledScopes).Count -gt 0) { $RecycleBinEnabled = $true }
    } catch { }

    # BitLocker Recovery Keys in AD
    $BitLockerKeysExist = $false
    try {
        $blKeys = Get-ADObject -Filter 'objectClass -eq "msFVE-RecoveryInformation"' -ResultSetSize 1 -ErrorAction SilentlyContinue
        if ($blKeys) { $BitLockerKeysExist = $true }
    } catch { }

    # DNS
    $DNSZones = @(); $DNSServer = $null
    try {
        if (Get-Module -ListAvailable -Name DnsServer) {
            Import-Module DnsServer -ErrorAction SilentlyContinue
            $DNSTargets = @($PrimaryDomain.PDCEmulator) + @($AllForestDCs | Where-Object { $_.HostName -ne $PrimaryDomain.PDCEmulator } | ForEach-Object { $_.HostName })
            foreach ($target in $DNSTargets) {
                try {
                    $DNSZones = Get-DnsServerZone -ComputerName $target -ErrorAction Stop |
                                Select-Object ZoneName, ZoneType, IsReverseLookupZone, IsDsIntegrated, ReplicationScope
                    $DNSServer = $target; break
                } catch { continue }
            }
            if ($DNSServer) { Write-Host "  [+] DNS zone data collected from $DNSServer." -ForegroundColor Green }
            else { Write-Host "  [i] No DNS server responded." -ForegroundColor Gray }
        } else { Write-Host "  [i] DnsServer module not available." -ForegroundColor Gray }
    } catch { }

    # DNS Forwarders
    $DNSForwarders = @()
    if ($DNSServer) {
        try {
            $fwd = Get-DnsServerForwarder -ComputerName $DNSServer -ErrorAction SilentlyContinue
            if ($fwd -and $fwd.IPAddress) { $DNSForwarders = $fwd.IPAddress | ForEach-Object { [string]$_ } }
        } catch { }
    }

    Write-Host "  [+] Forest-level data collected." -ForegroundColor Green

# ==============================================================================
# PER-DOMAIN COLLECTION
# ==============================================================================
    $AllDomainData = @{}
    $AllForestDCs  = @()
    $AllTrusts     = @()
    $ForestTotalUsers = 0; $ForestTotalComputers = 0; $ForestTotalGroups = 0; $ForestTotalGPOs = 0

    foreach ($domName in $ForestDomains) {
        Write-Host "  [*] Enumerating domain: $domName" -ForegroundColor Yellow
        $dd = @{}
        try {
            $dom = Get-ADDomain -Identity $domName -Server $domName -ErrorAction Stop
            $dd.DomainName = $dom.DNSRoot
            $dd.NetBIOS    = $dom.NetBIOSName
            $dd.DomainMode = Get-FriendlyFuncLevel $dom.DomainMode
            $dd.Parent     = if ($dom.ParentDomain) { $dom.ParentDomain } else { "(Forest Root)" }
            $dd.Children   = ($dom.ChildDomains | ForEach-Object { [string]$_ }) -join ', '
            $dd.DN         = $dom.DistinguishedName
            $dd.PDC        = $dom.PDCEmulator
            $dd.RID        = $dom.RIDMaster
            $dd.Infra      = $dom.InfrastructureMaster

            # DCs
            $dd.DCs = @()
            try {
                $domDCs = Get-ADDomainController -Filter * -Server $domName -ErrorAction Stop
                foreach ($dc in $domDCs) {
                    $dcObj = [PSCustomObject]@{
                        Name=''; HostName=''; Domain=$domName; IPv4Address=''; OperatingSystem='';
                        OSVersion=''; Site=''; Type=''; IsGlobalCatalog=$false; FSMORoles=''; Enabled=$true
                    }
                    $dcObj.Name            = $dc.Name
                    $dcObj.HostName        = $dc.HostName
                    $dcObj.IPv4Address     = $dc.IPv4Address
                    $dcObj.OperatingSystem = $dc.OperatingSystem
                    $dcObj.OSVersion       = $dc.OperatingSystemVersion
                    $dcObj.Site            = $dc.Site
                    $dcObj.Type            = if ($dc.IsReadOnly) { "RODC" } else { "RWDC" }
                    $dcObj.IsGlobalCatalog = $dc.IsGlobalCatalog
                    $dcObj.FSMORoles       = ($dc.OperationMasterRoles | ForEach-Object { [string]$_ }) -join ', '
                    $dcObj.Enabled         = $dc.Enabled
                    $dd.DCs += $dcObj
                    $AllForestDCs += $dcObj
                }
            } catch { Write-Host "    [i] Could not enumerate DCs for $domName" -ForegroundColor Gray }

            # Replication Failures per DC
            try {
                foreach ($dc in $dd.DCs) {
                    $fails = Get-ADReplicationFailure -Target $dc.HostName -ErrorAction SilentlyContinue
                    if ($fails) { $ReplFailures += $fails | Select-Object Server, Partner, FailureCount, FailureType, FirstFailureTime, LastError }
                }
            } catch { }

            # Trusts
            try {
                $domTrusts = Get-ADTrust -Filter * -Server $domName -ErrorAction SilentlyContinue
                foreach ($tr in $domTrusts) {
                    $AllTrusts += [PSCustomObject]@{
                        SourceDomain=$domName; TrustedDomain=$tr.Name; Direction=[string]$tr.Direction;
                        TrustType=[string]$tr.TrustType; Transitive=if($tr.DisallowTransivity){"No"}else{"Yes"};
                        SelectiveAuth=if($tr.SelectiveAuthentication){"Yes"}else{"No"};
                        IntraForest=if($tr.IntraForest){"Yes"}else{"No"}
                    }
                }
            } catch { }

            # Users
            $allU = Get-ADUser -Filter * -Server $domName -Properties Enabled,LockedOut,PasswordExpired,PasswordNeverExpires,LastLogonDate -ErrorAction SilentlyContinue
            $dd.TotalUsers    = @($allU).Count
            $dd.EnabledUsers  = @($allU | Where-Object { $_.Enabled -eq $true }).Count
            $dd.DisabledUsers = @($allU | Where-Object { $_.Enabled -eq $false }).Count
            $dd.LockedUsers   = @($allU | Where-Object { $_.LockedOut -eq $true }).Count
            $dd.PwdExpired    = @($allU | Where-Object { $_.PasswordExpired -eq $true }).Count
            $dd.PwdNeverExp   = @($allU | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
            $dd.NeverLoggedOn = @($allU | Where-Object { $_.Enabled -eq $true -and -not $_.LastLogonDate }).Count
            $dd.Inactive90    = @($allU | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt (Get-Date).AddDays(-90) }).Count
            $ForestTotalUsers += $dd.TotalUsers

            # Computers
            $allC = Get-ADComputer -Filter * -Server $domName -Properties Enabled,OperatingSystem,OperatingSystemVersion -ErrorAction SilentlyContinue
            $dd.TotalComputers    = @($allC).Count
            $dd.EnabledComputers  = @($allC | Where-Object { $_.Enabled -eq $true }).Count
            $dd.DisabledComputers = @($allC | Where-Object { $_.Enabled -eq $false }).Count
            $dd.Servers           = @($allC | Where-Object { $_.OperatingSystem -like "*Server*" }).Count
            $dd.Workstations      = @($allC | Where-Object { $_.OperatingSystem -and $_.OperatingSystem -notlike "*Server*" }).Count
            $ForestTotalComputers += $dd.TotalComputers

            # OS Distribution
            $dd.OSDist = @{}
            $allC | Where-Object { $_.OperatingSystem } | ForEach-Object {
                $os = $_.OperatingSystem
                if ($dd.OSDist.ContainsKey($os)) { $dd.OSDist[$os]++ } else { $dd.OSDist[$os] = 1 }
            }

            # Groups
            $allG = Get-ADGroup -Filter * -Server $domName -Properties GroupScope,GroupCategory,Members -ErrorAction SilentlyContinue
            $dd.TotalGroups   = @($allG).Count
            $dd.Security      = @($allG | Where-Object { $_.GroupCategory -eq 'Security' }).Count
            $dd.Distribution  = @($allG | Where-Object { $_.GroupCategory -eq 'Distribution' }).Count
            $dd.GlobalGrp     = @($allG | Where-Object { $_.GroupScope -eq 'Global' }).Count
            $dd.DomLocalGrp   = @($allG | Where-Object { $_.GroupScope -eq 'DomainLocal' }).Count
            $dd.UniversalGrp  = @($allG | Where-Object { $_.GroupScope -eq 'Universal' }).Count
            $dd.EmptyGrp      = @($allG | Where-Object { @($_.Members).Count -eq 0 }).Count
            $ForestTotalGroups += $dd.TotalGroups

            # Privileged Groups
            $privNames = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Server Operators','Backup Operators','Print Operators')
            $dd.PrivGroups = @()
            foreach ($pg in $privNames) {
                try {
                    $members = Get-ADGroupMember -Identity $pg -Server $domName -ErrorAction SilentlyContinue
                    $dd.PrivGroups += [PSCustomObject]@{ GroupName=$pg; MemberCount=@($members).Count; Members=($members | ForEach-Object { $_.SamAccountName }) -join ', ' }
                } catch { }
            }

            # Service Accounts (MSA, gMSA, dMSA)
            $dd.ServiceAccounts = @()
            try {
                # sMSA and gMSA
                $msas = Get-ADServiceAccount -Filter * -Server $domName -Properties Enabled,Created,ObjectClass,'msDS-ManagedPasswordInterval' -ErrorAction SilentlyContinue
                foreach ($m in $msas) {
                    $acctType = switch ($m.ObjectClass) {
                        'msDS-GroupManagedServiceAccount' { 'gMSA' }
                        'msDS-ManagedServiceAccount'     { 'sMSA' }
                        default { $m.ObjectClass }
                    }
                    $dd.ServiceAccounts += [PSCustomObject]@{
                        Name=$m.Name; SamAccountName=$m.SamAccountName; AccountType=$acctType;
                        Enabled=$m.Enabled; Created=$m.Created; PwdInterval=$m.'msDS-ManagedPasswordInterval'
                    }
                }
            } catch { }
            # dMSA (Windows Server 2025+)
            if ($dMSASupported) {
                try {
                    $dmsaClasses = @('msDS-DelegatedManagedServiceAccount','ms-DS-Delegated-Managed-Service-Account')
                    foreach ($cls in $dmsaClasses) {
                        $dmsas = Get-ADObject -Filter "objectClass -eq '$cls'" -SearchBase $dom.DistinguishedName -Server $domName -Properties Name,SamAccountName,Enabled,WhenCreated -ErrorAction SilentlyContinue
                        if ($dmsas) {
                            foreach ($d in $dmsas) {
                                $dd.ServiceAccounts += [PSCustomObject]@{
                                    Name=$d.Name; SamAccountName=$d.SamAccountName; AccountType='dMSA';
                                    Enabled=$d.Enabled; Created=$d.WhenCreated; PwdInterval='N/A'
                                }
                            }
                            break
                        }
                    }
                } catch { }
            }

            # GPOs
            $dd.GPOs = @(); $dd.TotalGPOs = 0; $dd.EnabledGPOs = 0; $dd.DisabledGPOs = 0; $dd.PartialGPOs = 0
            try {
                $dd.GPOs = Get-GPO -All -Domain $domName -ErrorAction Stop | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime, Description
                $dd.TotalGPOs    = @($dd.GPOs).Count
                $dd.EnabledGPOs  = @($dd.GPOs | Where-Object { $_.GpoStatus -eq 'AllSettingsEnabled' }).Count
                $dd.DisabledGPOs = @($dd.GPOs | Where-Object { $_.GpoStatus -eq 'AllSettingsDisabled' }).Count
                $dd.PartialGPOs  = @($dd.GPOs | Where-Object { $_.GpoStatus -notin @('AllSettingsEnabled','AllSettingsDisabled') }).Count
            } catch { }
            $ForestTotalGPOs += $dd.TotalGPOs

            # OUs
            $dd.OUs = Get-ADOrganizationalUnit -Filter * -Server $domName -Properties Description,ProtectedFromAccidentalDeletion -ErrorAction SilentlyContinue |
                      Select-Object Name, DistinguishedName, Description, ProtectedFromAccidentalDeletion

            # Default Password Policy
            $dd.PwdPolicy = Get-ADDefaultDomainPasswordPolicy -Server $domName -ErrorAction SilentlyContinue

            # Fine-Grained Password Policies
            $dd.FGPPs = @()
            try {
                $fgppResults = Get-ADFineGrainedPasswordPolicy -Filter * -Server $domName -ErrorAction Stop
                if ($fgppResults) {
                    $dd.FGPPs = @($fgppResults | Select-Object Name, Precedence, MinPasswordLength, MaxPasswordAge, MinPasswordAge, PasswordHistoryCount, ComplexityEnabled, LockoutThreshold, LockoutDuration, AppliesTo)
                }
            } catch {
                # Fallback: search by objectClass
                try {
                    $fgppAlt = Get-ADObject -Filter 'objectClass -eq "msDS-PasswordSettings"' -SearchBase "CN=Password Settings Container,CN=System,$($dom.DistinguishedName)" -Server $domName -Properties * -ErrorAction SilentlyContinue
                    if ($fgppAlt) {
                        $dd.FGPPs = @($fgppAlt | Select-Object @{N='Name';E={$_.Name}},
                            @{N='Precedence';E={$_.'msDS-PasswordSettingsPrecedence'}},
                            @{N='MinPasswordLength';E={$_.'msDS-MinimumPasswordLength'}},
                            @{N='MaxPasswordAge';E={$_.'msDS-MaximumPasswordAge'}},
                            @{N='MinPasswordAge';E={$_.'msDS-MinimumPasswordAge'}},
                            @{N='PasswordHistoryCount';E={$_.'msDS-PasswordHistoryLength'}},
                            @{N='ComplexityEnabled';E={$_.'msDS-PasswordComplexityEnabled'}},
                            @{N='LockoutThreshold';E={$_.'msDS-LockoutThreshold'}},
                            @{N='LockoutDuration';E={$_.'msDS-LockoutDuration'}})
                    }
                } catch { }
            }

            Write-Host "    Users:$($dd.TotalUsers) Computers:$($dd.TotalComputers) Groups:$($dd.TotalGroups) DCs:$($dd.DCs.Count) GPOs:$($dd.TotalGPOs) OUs:$(@($dd.OUs).Count) FGPPs:$($dd.FGPPs.Count) SvcAccts:$($dd.ServiceAccounts.Count)" -ForegroundColor Gray

            $AllDomainData[$domName] = $dd
            Write-Host "  [+] $domName -- $($dd.DomainMode)" -ForegroundColor Green

        } catch {
            Write-Host "  [!] Could not reach domain $domName : $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "  [+] Forest: $($ForestDomains.Count) domain(s), $($AllForestDCs.Count) DC(s) total." -ForegroundColor Green
    Write-Host "  [+] Schema, Tombstone, SYSVOL replication collected." -ForegroundColor Green
    Write-Host "  [+] User data collected ($ForestTotalUsers users)." -ForegroundColor Green
    Write-Host "  [+] Computer data collected ($ForestTotalComputers computers)." -ForegroundColor Green
    Write-Host "  [+] Group data collected ($ForestTotalGroups groups)." -ForegroundColor Green
    Write-Host "  [+] GPO data collected ($ForestTotalGPOs GPOs)." -ForegroundColor Green
    Write-Host "  [+] Privileged group membership collected." -ForegroundColor Green
    Write-Host "  [+] Service accounts collected (sMSA/gMSA/dMSA)." -ForegroundColor Green
    Write-Host "  [+] LAPS detection complete: $LAPSType" -ForegroundColor Green
    Write-Host "  [+] Data collection complete." -ForegroundColor Green

} catch {
    Write-Host "[!] Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Ensure you are on a domain-joined machine with RSAT." -ForegroundColor Red
    exit 1
}

# ==============================================================================
# BUILD PER-DOMAIN HTML SECTIONS
# ==============================================================================
$PerDomainHTML = [System.Text.StringBuilder]::new()

foreach ($domName in $ForestDomains) {
    if (-not $AllDomainData.ContainsKey($domName)) { continue }
    $dd = $AllDomainData[$domName]
    $domId = $domName -replace '[\.\s]','-'

    # DC Table
    $dcTbl = ConvertTo-HtmlTable -Data $dd.DCs -Properties Name, Domain, IPv4Address, Type, OperatingSystem, OSVersion, Site, IsGlobalCatalog, FSMORoles, Enabled

    # Priv Group Table
    $privTbl = if ($dd.PrivGroups.Count -gt 0) { ConvertTo-HtmlTable -Data $dd.PrivGroups -Properties GroupName, MemberCount, Members } else { '<p class="empty-note">No data.</p>' }

    # Service Accounts Table
    $svcTbl = if ($dd.ServiceAccounts.Count -gt 0) { ConvertTo-HtmlTable -Data $dd.ServiceAccounts -Properties Name, SamAccountName, AccountType, Enabled, Created, PwdInterval } else { '<p class="empty-note">No Managed Service Accounts (sMSA, gMSA, dMSA) found.</p>' }

    # GPO Table
    $gpoTbl = if ($dd.GPOs.Count -gt 0) { ConvertTo-HtmlTable -Data $dd.GPOs -Properties DisplayName, GpoStatus, CreationTime, ModificationTime, Description } else { '<p class="empty-note">No GPOs found or GPMC not available.</p>' }

    # OU Table
    $ouTbl = if ($dd.OUs.Count -gt 0) { ConvertTo-HtmlTable -Data $dd.OUs -Properties Name, DistinguishedName, Description, ProtectedFromAccidentalDeletion } else { '<p class="empty-note">No OUs.</p>' }

    # FGPP Table
    $fgppTbl = if ($dd.FGPPs.Count -gt 0) { ConvertTo-HtmlTable -Data $dd.FGPPs -Properties Name, Precedence, MinPasswordLength, MaxPasswordAge, MinPasswordAge, PasswordHistoryCount, ComplexityEnabled, LockoutThreshold, LockoutDuration } else { '<p class="empty-note">No Fine-Grained Password Policies.</p>' }

    # Password Policy
    $pp = $dd.PwdPolicy
    $ppHTML = ""
    if ($pp) {
        $ppHTML = @"
<div class="info-grid">
  <div class="info-card"><span class="info-label">Min Password Length</span><span class="info-value">$($pp.MinPasswordLength)</span></div>
  <div class="info-card"><span class="info-label">Password History</span><span class="info-value">$($pp.PasswordHistoryCount)</span></div>
  <div class="info-card"><span class="info-label">Max Password Age</span><span class="info-value">$($pp.MaxPasswordAge)</span></div>
  <div class="info-card"><span class="info-label">Min Password Age</span><span class="info-value">$($pp.MinPasswordAge)</span></div>
  <div class="info-card"><span class="info-label">Complexity</span><span class="info-value">$($pp.ComplexityEnabled)</span></div>
  <div class="info-card"><span class="info-label">Reversible Encryption</span><span class="info-value">$($pp.ReversibleEncryptionEnabled)</span></div>
  <div class="info-card"><span class="info-label">Lockout Threshold</span><span class="info-value">$($pp.LockoutThreshold)</span></div>
  <div class="info-card"><span class="info-label">Lockout Duration</span><span class="info-value">$($pp.LockoutDuration)</span></div>
  <div class="info-card"><span class="info-label">Lockout Window</span><span class="info-value">$($pp.LockoutObservationWindow)</span></div>
</div>
"@
    }

    # Service Account Summary
    $sMSACount = @($dd.ServiceAccounts | Where-Object { $_.AccountType -eq 'sMSA' }).Count
    $gMSACount = @($dd.ServiceAccounts | Where-Object { $_.AccountType -eq 'gMSA' }).Count
    $dMSACount = @($dd.ServiceAccounts | Where-Object { $_.AccountType -eq 'dMSA' }).Count

    [void]$PerDomainHTML.Append(@"

<!-- ===== DOMAIN: $domName ================================================= -->
<div id="dom-$domId" class="section">
  <h2 class="section-title domain-header"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#127760;</span> Domain: $domName</h2>
  <div class="info-grid" style="margin-bottom:18px">
    <div class="info-card"><span class="info-label">NetBIOS</span><span class="info-value">$($dd.NetBIOS)</span></div>
    <div class="info-card"><span class="info-label">Functional Level</span><span class="info-value">$($dd.DomainMode)</span></div>
    <div class="info-card"><span class="info-label">Parent Domain</span><span class="info-value">$($dd.Parent)</span></div>
    <div class="info-card"><span class="info-label">Child Domains</span><span class="info-value">$(if($dd.Children){$dd.Children}else{'(none)'})</span></div>
    <div class="info-card"><span class="info-label">PDC Emulator</span><span class="info-value">$($dd.PDC)</span></div>
    <div class="info-card"><span class="info-label">RID Master</span><span class="info-value">$($dd.RID)</span></div>
    <div class="info-card"><span class="info-label">Infrastructure Master</span><span class="info-value">$($dd.Infra)</span></div>
  </div>

  <!-- DCs -->
  <h3 class="sub-header">Domain Controllers ($($dd.DCs.Count))</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($dd.DCs.Count)</div><div class="card-label">Total DCs</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$(@($dd.DCs | Where-Object {$_.Type -eq 'RWDC'}).Count)</div><div class="card-label">RWDC</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$(@($dd.DCs | Where-Object {$_.Type -eq 'RODC'}).Count)</div><div class="card-label">RODC</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$(@($dd.DCs | Where-Object {$_.IsGlobalCatalog}).Count)</div><div class="card-label">Global Catalog</div></div>
  </div>
  $dcTbl

  <!-- Users -->
  <h3 class="sub-header">User Accounts ($($dd.TotalUsers))</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($dd.TotalUsers)</div><div class="card-label">Total</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$($dd.EnabledUsers)</div><div class="card-label">Enabled</div></div>
    <div class="card"><div class="card-val" style="color:var(--red)">$($dd.DisabledUsers)</div><div class="card-label">Disabled</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$($dd.LockedUsers)</div><div class="card-label">Locked</div></div>
    <div class="card"><div class="card-val" style="color:var(--orange)">$($dd.PwdExpired)</div><div class="card-label">Pwd Expired</div></div>
    <div class="card"><div class="card-val" style="color:var(--pink)">$($dd.PwdNeverExp)</div><div class="card-label">Pwd Never Exp</div></div>
    <div class="card"><div class="card-val" style="color:var(--purple)">$($dd.NeverLoggedOn)</div><div class="card-label">Never Logged On</div></div>
    <div class="card"><div class="card-val" style="color:var(--text-dim)">$($dd.Inactive90)</div><div class="card-label">Inactive 90d+</div></div>
  </div>

  <!-- Computers -->
  <h3 class="sub-header">Computer Accounts ($($dd.TotalComputers))</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($dd.TotalComputers)</div><div class="card-label">Total</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$($dd.EnabledComputers)</div><div class="card-label">Enabled</div></div>
    <div class="card"><div class="card-val" style="color:var(--red)">$($dd.DisabledComputers)</div><div class="card-label">Disabled</div></div>
    <div class="card"><div class="card-val" style="color:var(--purple)">$($dd.Servers)</div><div class="card-label">Servers</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$($dd.Workstations)</div><div class="card-label">Workstations</div></div>
  </div>

  <!-- Groups -->
  <h3 class="sub-header">Groups ($($dd.TotalGroups))</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($dd.TotalGroups)</div><div class="card-label">Total</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$($dd.Security)</div><div class="card-label">Security</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$($dd.Distribution)</div><div class="card-label">Distribution</div></div>
    <div class="card"><div class="card-val" style="color:var(--purple)">$($dd.GlobalGrp)</div><div class="card-label">Global</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$($dd.DomLocalGrp)</div><div class="card-label">Domain Local</div></div>
    <div class="card"><div class="card-val" style="color:var(--pink)">$($dd.UniversalGrp)</div><div class="card-label">Universal</div></div>
    <div class="card"><div class="card-val" style="color:var(--text-dim)">$($dd.EmptyGrp)</div><div class="card-label">Empty</div></div>
  </div>

  <!-- Privileged Groups -->
  <h3 class="sub-header">Privileged Groups</h3>
  $privTbl

  <!-- Service Accounts -->
  <h3 class="sub-header">Service Accounts (sMSA: $sMSACount | gMSA: $gMSACount | dMSA: $dMSACount)</h3>
  $svcTbl

  <!-- GPOs -->
  <h3 class="sub-header">Group Policy Objects ($($dd.TotalGPOs))</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($dd.TotalGPOs)</div><div class="card-label">Total</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$($dd.EnabledGPOs)</div><div class="card-label">All Enabled</div></div>
    <div class="card"><div class="card-val" style="color:var(--red)">$($dd.DisabledGPOs)</div><div class="card-label">All Disabled</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$($dd.PartialGPOs)</div><div class="card-label">Partial</div></div>
  </div>
  $gpoTbl

  <!-- OUs -->
  <h3 class="sub-header">Organizational Units ($(@($dd.OUs).Count))</h3>
  $ouTbl

  <!-- Password Policy -->
  <h3 class="sub-header">Default Domain Password Policy</h3>
  $ppHTML
  <h3 class="sub-header" style="margin-top:16px">Fine-Grained Password Policies</h3>
  $fgppTbl
</div>
"@)
}

# Build sidebar domain nav links
$DomainNavLinks = ($ForestDomains | ForEach-Object {
    $id = $_ -replace '[\.\s]','-'
    "    <a href=`"#dom-$id`">$_</a>"
}) -join "`n"

# Trust table
$TrustTable = if ($AllTrusts.Count -gt 0) { ConvertTo-HtmlTable -Data $AllTrusts -Properties SourceDomain, TrustedDomain, Direction, TrustType, Transitive, SelectiveAuth, IntraForest } else { '<p class="empty-note">No trusts configured.</p>' }

# Forest-wide ALL DCs table
$AllDCsTable = ConvertTo-HtmlTable -Data $AllForestDCs -Properties Name, Domain, IPv4Address, Type, OperatingSystem, OSVersion, Site, IsGlobalCatalog, FSMORoles, Enabled

# Domain Summary table
$DomainSummaryData = foreach ($domName in $ForestDomains) {
    if (-not $AllDomainData.ContainsKey($domName)) { continue }
    $dd = $AllDomainData[$domName]
    [PSCustomObject]@{
        Domain=$dd.DomainName; NetBIOS=$dd.NetBIOS; FunctionalLevel=$dd.DomainMode;
        Parent=$dd.Parent; DCs=$dd.DCs.Count; Users=$dd.TotalUsers;
        Computers=$dd.TotalComputers; Groups=$dd.TotalGroups; GPOs=$dd.TotalGPOs
    }
}
$DomainSummaryTable = ConvertTo-HtmlTable -Data $DomainSummaryData -Properties Domain, NetBIOS, FunctionalLevel, Parent, DCs, Users, Computers, Groups, GPOs

# Replication tables
$ReplPartnerTable = if ($ReplPartners.Count -gt 0) { ConvertTo-HtmlTable -Data $ReplPartners -Properties Server, Partner, PartnerType, LastReplicationAttempt, LastReplicationSuccess, LastReplicationResult, ConsecutiveReplicationFailures } else { '<p class="empty-note">No data.</p>' }
$ReplFailureTable = if ($ReplFailures.Count -gt 0) { ConvertTo-HtmlTable -Data $ReplFailures -Properties Server, Partner, FailureCount, FailureType, FirstFailureTime, LastError } else { '<p class="empty-note">No replication failures.</p>' }
$ReplConnTable    = if ($ReplConnections.Count -gt 0) { ConvertTo-HtmlTable -Data $ReplConnections -Properties Name, ReplicateFromDirectoryServer, ReplicateToDirectoryServer, AutoGenerated, Enabled } else { '<p class="empty-note">No data.</p>' }
$OptFeatTable     = if ($OptionalFeatures) { ConvertTo-HtmlTable -Data $OptionalFeatures -Properties Name, EnabledScopes, IsDisableable } else { '<p class="empty-note">No data.</p>' }
$DNSTable         = if ($DNSZones.Count -gt 0) { ConvertTo-HtmlTable -Data $DNSZones -Properties ZoneName, ZoneType, IsReverseLookupZone, IsDsIntegrated, ReplicationScope } else { '<p class="empty-note">DNS zones not available.</p>' }
$SiteTable        = ConvertTo-HtmlTable -Data $ADSites -Properties Name, Description
$SubnetTable      = ConvertTo-HtmlTable -Data $ADSubnets -Properties Name, Site, Location, Description
$SiteLinkTable    = ConvertTo-HtmlTable -Data $ADSiteLinks -Properties Name, Cost, ReplicationFrequencyInMinutes, SitesIncluded

# AAD Connect / Entra Connect table
$AADConnectTable = if ($AADConnectServers.Count -gt 0) { ConvertTo-HtmlTable -Data $AADConnectServers -Properties DetectionMethod, ServiceAccount, ServerName, Enabled, Created, Description } else { '<p class="empty-note">No Entra Connect / Azure AD Connect service accounts detected.</p>' }

# ADCS table
$ADCSTable = if ($ADCSData.Count -gt 0) { ConvertTo-HtmlTable -Data $ADCSData -Properties CAName, Server, Created } else { '<p class="empty-note">No AD Certificate Services detected.</p>' }

# ==============================================================================
# CHART & DIAGRAM DATA PREPARATION
# ==============================================================================

# Aggregate forest-wide user/computer/group stats for charts
$FW_EnabledUsers  = 0; $FW_DisabledUsers = 0; $FW_LockedUsers = 0; $FW_PwdExpired = 0
$FW_PwdNeverExp   = 0; $FW_NeverLoggedOn = 0; $FW_Inactive90 = 0
$FW_EnabledComp   = 0; $FW_DisabledComp = 0; $FW_Servers = 0; $FW_Workstations = 0
$FW_SecGrp = 0; $FW_DistGrp = 0; $FW_GlobGrp = 0; $FW_DLGrp = 0; $FW_UnivGrp = 0; $FW_EmptyGrp = 0
$FW_GPOEnabled = 0; $FW_GPODisabled = 0; $FW_GPOPartial = 0
$FW_OSDist = @{}

foreach ($domName in $ForestDomains) {
    if (-not $AllDomainData.ContainsKey($domName)) { continue }
    $dd = $AllDomainData[$domName]
    $FW_EnabledUsers  += $dd.EnabledUsers;  $FW_DisabledUsers += $dd.DisabledUsers
    $FW_LockedUsers   += $dd.LockedUsers;   $FW_PwdExpired    += $dd.PwdExpired
    $FW_PwdNeverExp   += $dd.PwdNeverExp;   $FW_NeverLoggedOn += $dd.NeverLoggedOn
    $FW_Inactive90    += $dd.Inactive90
    $FW_EnabledComp   += $dd.EnabledComputers; $FW_DisabledComp += $dd.DisabledComputers
    $FW_Servers       += $dd.Servers;       $FW_Workstations  += $dd.Workstations
    $FW_SecGrp += $dd.Security; $FW_DistGrp += $dd.Distribution
    $FW_GlobGrp += $dd.GlobalGrp; $FW_DLGrp += $dd.DomLocalGrp; $FW_UnivGrp += $dd.UniversalGrp; $FW_EmptyGrp += $dd.EmptyGrp
    $FW_GPOEnabled += $dd.EnabledGPOs; $FW_GPODisabled += $dd.DisabledGPOs; $FW_GPOPartial += $dd.PartialGPOs
    foreach ($k in $dd.OSDist.Keys) {
        if ($FW_OSDist.ContainsKey($k)) { $FW_OSDist[$k] += $dd.OSDist[$k] } else { $FW_OSDist[$k] = $dd.OSDist[$k] }
    }
}

$UserChartJSON = '{"Enabled":' + $FW_EnabledUsers + ',"Disabled":' + $FW_DisabledUsers + ',"Locked":' + $FW_LockedUsers + ',"PwdExpired":' + $FW_PwdExpired + ',"PwdNeverExp":' + $FW_PwdNeverExp + ',"NeverLoggedOn":' + $FW_NeverLoggedOn + ',"Inactive90d":' + $FW_Inactive90 + '}'
$CompChartJSON = '{"Enabled":' + $FW_EnabledComp + ',"Disabled":' + $FW_DisabledComp + ',"Servers":' + $FW_Servers + ',"Workstations":' + $FW_Workstations + '}'
$GroupChartJSON = '{"Security":' + $FW_SecGrp + ',"Distribution":' + $FW_DistGrp + ',"Global":' + $FW_GlobGrp + ',"DomainLocal":' + $FW_DLGrp + ',"Universal":' + $FW_UnivGrp + ',"Empty":' + $FW_EmptyGrp + '}'
$GPOChartJSON = '{"Enabled":' + $FW_GPOEnabled + ',"Disabled":' + $FW_GPODisabled + ',"Partial":' + $FW_GPOPartial + '}'
$OSDistJSON = ($FW_OSDist.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { [PSCustomObject]@{os=$_.Key;count=$_.Value} } | ConvertTo-Json -Depth 2 -Compress)
if (-not $OSDistJSON) { $OSDistJSON = '[]' }

# DC info JSON
$DCInfoJSON = ($AllForestDCs | ForEach-Object {
    [PSCustomObject]@{
        name=$_.Name; ip=$_.IPv4Address; os=$_.OperatingSystem; osver=$_.OSVersion;
        domain=$_.Domain; site=$_.Site; gc=[bool]$_.IsGlobalCatalog;
        rodc=($_.Type -eq 'RODC'); roles=if($_.FSMORoles){@($_.FSMORoles -split ', ')}else{@()}
    }
} | ConvertTo-Json -Depth 3 -Compress)

# Site topology JSON
$SiteTopologyJSON = @{
    sites=@($ADSites | ForEach-Object { @{name=$_.Name;desc="$($_.Description)"} })
    subnets=@($ADSubnets | ForEach-Object { @{name=$_.Name;site="$($_.Site)";loc="$($_.Location)"} })
    sitelinks=@($ADSiteLinks | ForEach-Object { @{name=$_.Name;cost=$_.Cost;freq=$_.ReplicationFrequencyInMinutes;sites=@($_.SitesIncluded | ForEach-Object {[string]$_})} })
} | ConvertTo-Json -Depth 4 -Compress

# Trust JSON
$TrustJSON = "[]"
if ($AllTrusts.Count -gt 0) {
    $seen=@{}; $uniq=@()
    foreach ($t in $AllTrusts) {
        $k="$($t.SourceDomain)->$($t.TrustedDomain)"
        $kr="$($t.TrustedDomain)->$($t.SourceDomain)"
        if(-not $seen.ContainsKey($k) -and -not $seen.ContainsKey($kr)){$seen[$k]=$true;$uniq+=$t}
    }
    $TrustJSON = ($uniq | ForEach-Object {
        [PSCustomObject]@{source=$_.SourceDomain;name=$_.TrustedDomain;direction=$_.Direction;type=$_.TrustType;transitive=($_.Transitive -eq 'Yes');intra=($_.IntraForest -eq 'Yes')}
    } | ConvertTo-Json -Depth 3 -Compress)
}

# OU tree JSON (all domains combined)
$AllOUs = @()
foreach ($domName in $ForestDomains) {
    if (-not $AllDomainData.ContainsKey($domName)) { continue }
    $AllDomainData[$domName].OUs | ForEach-Object {
        $depth = (($_.DistinguishedName -split '(?<!\\),') | Where-Object { $_ -match '^OU=' }).Count
        $AllOUs += [PSCustomObject]@{name=$_.Name;dn=$_.DistinguishedName;depth=$depth;prot=[bool]$_.ProtectedFromAccidentalDeletion;domain=$domName}
    }
}
$OUTreeJSON = ($AllOUs | ConvertTo-Json -Depth 3 -Compress)
if (-not $OUTreeJSON) { $OUTreeJSON = '[]' }

# Kerberos defaults
$KerbMaxTicketAge  = "10 hours (default)"
$KerbMaxRenewAge   = "7 days (default)"
$KerbMaxServiceAge = "600 minutes (default)"
$KerbMaxClockSkew  = "5 minutes (default)"

# Per-domain comparison data
$DomainCompJSON = ($ForestDomains | ForEach-Object {
    if ($AllDomainData.ContainsKey($_)) {
        $d = $AllDomainData[$_]
        [PSCustomObject]@{domain=$_;users=$d.TotalUsers;computers=$d.TotalComputers;groups=$d.TotalGroups;dcs=$d.DCs.Count;gpos=$d.TotalGPOs}
    }
} | ConvertTo-Json -Depth 2 -Compress)
if (-not $DomainCompJSON) { $DomainCompJSON = '[]' }

# DC distribution by site
$DCSiteDistJSON = @{}
foreach ($dc in $AllForestDCs) {
    $s = if ($dc.Site) { $dc.Site } else { "Unknown" }
    if ($DCSiteDistJSON.ContainsKey($s)) { $DCSiteDistJSON[$s]++ } else { $DCSiteDistJSON[$s] = 1 }
}
$DCSiteDistStr = '{' + (($DCSiteDistJSON.GetEnumerator() | ForEach-Object { '"' + $_.Key + '":' + $_.Value }) -join ',') + '}'

# DC type distribution
$DCTypeJSON = '{"RWDC":' + @($AllForestDCs | Where-Object {$_.Type -eq 'RWDC'}).Count + ',"RODC":' + @($AllForestDCs | Where-Object {$_.Type -eq 'RODC'}).Count + '}'

# Privileged groups aggregated
$AllPrivGroups = @()
foreach ($domName in $ForestDomains) {
    if ($AllDomainData.ContainsKey($domName)) {
        foreach ($pg in $AllDomainData[$domName].PrivGroups) {
            $AllPrivGroups += [PSCustomObject]@{name="$($pg.GroupName) ($domName)";count=$pg.MemberCount}
        }
    }
}
$PrivGroupJSON = ($AllPrivGroups | Where-Object { $_.count -gt 0 } | Sort-Object count -Descending | Select-Object -First 15 | ConvertTo-Json -Depth 2 -Compress)
if (-not $PrivGroupJSON) { $PrivGroupJSON = '[]' }

# ==============================================================================
# HTML OUTPUT
# ==============================================================================
$HTML = @"
<!--
================================================================================
  ADCanvas -- Active Directory Documentation Report
  Generated : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Author    : Santhosh Sivarajan, Microsoft MVP
  Email     : santhosh@sivarajan.com
================================================================================
-->
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="author" content="Santhosh Sivarajan, Microsoft MVP"/>
<title>ADCanvas -- $($Forest.Name)</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f172a;--surface:#1e293b;--surface2:#273548;--border:#334155;
  --text:#e2e8f0;--text-dim:#94a3b8;--accent:#60a5fa;--accent2:#22d3ee;
  --green:#34d399;--red:#f87171;--amber:#fbbf24;--purple:#a78bfa;
  --pink:#f472b6;--orange:#fb923c;--accent-bg:rgba(96,165,250,.1);
  --radius:8px;--shadow:0 1px 3px rgba(0,0,0,.3);
  --font-body:'Segoe UI',system-ui,-apple-system,sans-serif;
}
html{scroll-behavior:smooth;font-size:15px}
body{font-family:var(--font-body);background:var(--bg);color:var(--text);line-height:1.65;min-height:100vh}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrapper{display:flex;min-height:100vh}
.sidebar{position:fixed;top:0;left:0;width:260px;height:100vh;background:var(--surface);border-right:1px solid var(--border);overflow-y:auto;padding:20px 0;z-index:100;box-shadow:2px 0 12px rgba(0,0,0,.3)}
.sidebar::-webkit-scrollbar{width:4px}.sidebar::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
.sidebar .logo{padding:0 18px 14px;border-bottom:1px solid var(--border);margin-bottom:8px}
.sidebar .logo h2{font-size:1.05rem;color:var(--accent);font-weight:700}
.sidebar .logo p{font-size:.68rem;color:var(--text-dim);margin-top:2px}
.sidebar nav a{display:block;padding:5px 18px 5px 22px;font-size:.78rem;color:var(--text-dim);border-left:3px solid transparent;transition:all .15s}
.sidebar nav a:hover,.sidebar nav a.active{color:var(--accent);background:rgba(96,165,250,.08);border-left-color:var(--accent);text-decoration:none}
.sidebar nav .nav-group{font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--accent2);padding:10px 18px 2px;font-weight:700}
.main{margin-left:260px;flex:1;padding:24px 32px 50px;max-width:1200px}
.section{margin-bottom:36px}
.section-title{font-size:1.25rem;font-weight:700;color:var(--text);margin-bottom:4px;padding-bottom:8px;border-bottom:2px solid var(--border);display:flex;align-items:center;gap:8px}
.section-title .icon{width:24px;height:24px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:.8rem;flex-shrink:0}
.domain-header{font-size:1.35rem;color:var(--accent);border-bottom-color:var(--accent);margin-top:24px}
.sub-header{font-size:.92rem;color:var(--text);margin:16px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--border)}
.section-desc{color:var(--text-dim);font-size:.84rem;margin-bottom:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:16px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow)}
.card:hover{border-color:var(--accent)}
.card .card-val{font-size:1.5rem;font-weight:800;line-height:1.1}
.card .card-label{font-size:.68rem;color:var(--text-dim);margin-top:2px;text-transform:uppercase;letter-spacing:.05em}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px}
.info-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px 14px;box-shadow:var(--shadow)}
.info-label{display:block;font-size:.68rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}
.info-value{font-size:.95rem;font-weight:600;color:var(--text)}
.table-wrap{overflow-x:auto;margin-bottom:8px;border-radius:var(--radius);border:1px solid var(--border);box-shadow:var(--shadow)}
table{width:100%;border-collapse:collapse;font-size:.78rem}
thead{background:var(--accent-bg)}
th{text-align:left;padding:8px 10px;font-weight:600;color:var(--accent);white-space:nowrap;border-bottom:2px solid var(--border)}
td{padding:7px 10px;border-bottom:1px solid var(--border);color:var(--text-dim);max-width:360px;overflow:hidden;text-overflow:ellipsis}
tbody tr:hover{background:rgba(96,165,250,.06)}
tbody tr:nth-child(even){background:var(--surface2)}
.empty-note{color:var(--text-dim);font-style:italic;padding:8px 0}
.exec-summary{background:linear-gradient(135deg,#1e293b 0%,#1e3a5f 100%);border:1px solid #334155;border-radius:var(--radius);padding:22px 26px;margin-bottom:28px;box-shadow:var(--shadow)}
.exec-summary h2{font-size:1.1rem;color:var(--accent);margin-bottom:8px}
.exec-summary p{color:var(--text-dim);font-size:.86rem;line-height:1.7;margin-bottom:6px}
.exec-kv{display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:2px 8px;margin:2px;font-size:.78rem;color:var(--text)}
.exec-kv strong{color:var(--accent2)}
.fsmo-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:8px;margin-bottom:14px}
.fsmo-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;text-align:center}
.fsmo-card .role{font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;color:var(--accent);margin-bottom:4px;font-weight:700}
.fsmo-card .holder{font-size:.82rem;color:var(--text);font-weight:600;word-break:break-all}
.footer{margin-top:36px;padding:18px 0;border-top:1px solid var(--border);text-align:center;color:var(--text-dim);font-size:.74rem}
.footer a{color:var(--accent)}
@media print{.sidebar{display:none}.main{margin-left:0}body{background:#fff;color:#222}
  .card,.info-card,.exec-summary,.fsmo-card,.diagram-container{background:#f9f9f9;border-color:#ccc;color:#222}
  .card-val,.info-value,.section-title,.domain-header{color:#222}.card-label,.info-label,.section-desc{color:#555}
  th{color:#333;background:#eee}td{color:#444}}
@media(max-width:900px){.sidebar{display:none}.main{margin-left:0;padding:14px}}
</style>
</head>
<body>
<div class="wrapper">
<aside class="sidebar">
  <div class="logo">
    <h2>ADCanvas</h2>
    <p>Developed by Santhosh Sivarajan</p>
    <p style="margin-top:6px">Forest: <strong style="color:#e2e8f0">$($Forest.Name)</strong></p>
  </div>
  <nav>
    <div class="nav-group">Overview</div>
    <a href="#exec-summary">Executive Summary</a>
    <a href="#forest-config">Forest Configuration</a>
    <a href="#schema-info">Schema &amp; Directory</a>
    <a href="#fsmo">FSMO Roles</a>
    <div class="nav-group">Domains ($($ForestDomains.Count))</div>
$DomainNavLinks
    <div class="nav-group">Infrastructure</div>
    <a href="#replication">Replication Status</a>
    <a href="#sites-subnets">Sites &amp; Subnets</a>
    <a href="#dns">DNS Zones</a>
    <a href="#trusts">Trust Relationships</a>
    <div class="nav-group">Security</div>
    <a href="#entra-connect">Entra Connect</a>
    <a href="#adcs">Certificate Services</a>
    <a href="#kerberos">Kerberos Policy</a>
    <a href="#laps">LAPS Status</a>
    <a href="#ad-health">AD Health Indicators</a>
    <a href="#optional-features">Optional Features</a>
    <div class="nav-group">Visuals</div>
    <a href="#charts-overview">Forest-Wide Charts</a>
    <a href="#diagrams">Diagrams</a>
  </nav>
</aside>
<main class="main">

<!-- EXECUTIVE SUMMARY -->
<div id="exec-summary" class="section">
  <div class="exec-summary">
    <h2>Executive Summary -- $($Forest.Name)</h2>
    <p>Point-in-time documentation of the Active Directory forest <strong>$($Forest.Name)</strong>, generated on <strong>$(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm")</strong>. All domains, domain controllers, user/computer/group objects, service accounts, GPOs, trusts, replication, and security settings are documented below on a per-domain basis.</p>
    <p>
      <span class="exec-kv"><strong>Forest:</strong> $($Forest.Name)</span>
      <span class="exec-kv"><strong>Schema:</strong> $SchemaVersion ($SchemaOS)</span>
      <span class="exec-kv"><strong>Forest Level:</strong> $ForestModeDisplay</span>
      <span class="exec-kv"><strong>Domains:</strong> $($ForestDomains.Count)</span>
      <span class="exec-kv"><strong>Total DCs:</strong> $($AllForestDCs.Count)</span>
      <span class="exec-kv"><strong>Sites:</strong> $($ADSites.Count)</span>
      <span class="exec-kv"><strong>Users:</strong> $ForestTotalUsers</span>
      <span class="exec-kv"><strong>Computers:</strong> $ForestTotalComputers</span>
      <span class="exec-kv"><strong>Groups:</strong> $ForestTotalGroups</span>
      <span class="exec-kv"><strong>GPOs:</strong> $ForestTotalGPOs</span>
      <span class="exec-kv"><strong>Trusts:</strong> $($AllTrusts.Count)</span>
      <span class="exec-kv"><strong>SYSVOL:</strong> $SysvolReplType</span>
      <span class="exec-kv"><strong>LAPS:</strong> $LAPSType</span>
      <span class="exec-kv"><strong>dMSA Schema:</strong> $(if($dMSASupported){'Supported'}else{'N/A'})</span>
      <span class="exec-kv"><strong>Entra Connect:</strong> $(if($AADConnectServers.Count -gt 0){"$($AADConnectServers.Count) detected"}else{'Not detected'})</span>
      <span class="exec-kv"><strong>ADCS CAs:</strong> $(if($ADCSData.Count -gt 0){"$($ADCSData.Count)"}else{'None'})</span>
      <span class="exec-kv"><strong>Recycle Bin:</strong> $(if($RecycleBinEnabled){'Enabled'}else{'Disabled'})</span>
      <span class="exec-kv"><strong>BitLocker in AD:</strong> $(if($BitLockerKeysExist){'Yes'}else{'No'})</span>
    </p>
  </div>
</div>

<!-- FOREST CONFIG -->
<div id="forest-config" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#127794;</span> Forest Configuration</h2>
  <div class="info-grid">
    <div class="info-card"><span class="info-label">Forest Name</span><span class="info-value">$($Forest.Name)</span></div>
    <div class="info-card"><span class="info-label">Forest Root Domain</span><span class="info-value">$ForestRootDomain</span></div>
    <div class="info-card"><span class="info-label">Forest Functional Level</span><span class="info-value">$ForestModeDisplay</span></div>
    <div class="info-card"><span class="info-label">Total Domains</span><span class="info-value">$($ForestDomains.Count)</span></div>
    <div class="info-card"><span class="info-label">Global Catalogs</span><span class="info-value">$(($GlobalCatalogs | ForEach-Object {[string]$_}) -join ', ')</span></div>
    <div class="info-card"><span class="info-label">UPN Suffixes</span><span class="info-value">$(if($UPNSuffixes){($UPNSuffixes | ForEach-Object {[string]$_}) -join ', '}else{'(default only)'})</span></div>
    <div class="info-card"><span class="info-label">SPN Suffixes</span><span class="info-value">$(if($SPNSuffixes){($SPNSuffixes | ForEach-Object {[string]$_}) -join ', '}else{'(none)'})</span></div>
  </div>

  <h3 class="sub-header">Domain Summary (All Domains in Forest)</h3>
  $DomainSummaryTable

  <h3 class="sub-header">All Domain Controllers ($($AllForestDCs.Count) across all domains)</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($AllForestDCs.Count)</div><div class="card-label">Total DCs</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$(@($AllForestDCs | Where-Object {$_.Type -eq 'RWDC'}).Count)</div><div class="card-label">RWDC</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$(@($AllForestDCs | Where-Object {$_.Type -eq 'RODC'}).Count)</div><div class="card-label">RODC</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$(@($AllForestDCs | Where-Object {$_.IsGlobalCatalog}).Count)</div><div class="card-label">Global Catalogs</div></div>
  </div>
  $AllDCsTable
</div>

<!-- SCHEMA -->
<div id="schema-info" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(167,139,250,.15);color:var(--purple)">&#128736;</span> Schema &amp; Directory Configuration</h2>
  <div class="info-grid">
    <div class="info-card"><span class="info-label">Schema Version</span><span class="info-value">$SchemaVersion ($SchemaOS)</span></div>
    <div class="info-card"><span class="info-label">Tombstone Lifetime</span><span class="info-value">$TombstoneLife days</span></div>
    <div class="info-card"><span class="info-label">Garbage Collection</span><span class="info-value">$GarbageCollect hours</span></div>
    <div class="info-card"><span class="info-label">SYSVOL Replication</span><span class="info-value">$SysvolReplType</span></div>
    <div class="info-card"><span class="info-label">dMSA Schema Support</span><span class="info-value">$(if($dMSASupported){'Yes (Server 2025+)'}else{'No'})</span></div>
  </div>
</div>

<!-- FSMO -->
<div id="fsmo" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(167,139,250,.15);color:var(--purple)">&#9733;</span> Forest-Wide FSMO Roles</h2>
  <div class="fsmo-grid">
    <div class="fsmo-card"><div class="role">Schema Master</div><div class="holder">$SchemaMaster</div></div>
    <div class="fsmo-card"><div class="role">Domain Naming Master</div><div class="holder">$NamingMaster</div></div>
  </div>
  <p class="section-desc">Per-domain FSMO roles (PDC Emulator, RID Master, Infrastructure Master) are shown in each domain section below.</p>
</div>

<!-- PER-DOMAIN SECTIONS -->
$($PerDomainHTML.ToString())

<!-- REPLICATION -->
<div id="replication" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(52,211,153,.15);color:var(--green)">&#128259;</span> AD Replication Status</h2>
  <h3 class="sub-header">Replication Partners</h3>
  $ReplPartnerTable
  <h3 class="sub-header">Replication Failures</h3>
  $ReplFailureTable
  <h3 class="sub-header">Connection Objects</h3>
  $ReplConnTable
</div>

<!-- SITES -->
<div id="sites-subnets" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(34,211,238,.15);color:var(--accent2)">&#127760;</span> Sites &amp; Subnets</h2>
  <h3 class="sub-header">Sites ($($ADSites.Count))</h3>
  $SiteTable
  <h3 class="sub-header">Subnets ($($ADSubnets.Count))</h3>
  $SubnetTable
  <h3 class="sub-header">Site Links</h3>
  $SiteLinkTable
</div>

<!-- DNS -->
<div id="dns" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128268;</span> DNS Zones$(if($DNSServer){" (from $DNSServer)"})</h2>
  $DNSTable
</div>

<!-- TRUSTS -->
<div id="trusts" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(244,114,182,.15);color:var(--pink)">&#128279;</span> Trust Relationships</h2>
  <p class="section-desc">All trust relationships across all domains in the forest.</p>
  $TrustTable
</div>

<!-- ENTRA CONNECT / AAD CONNECT -->
<div id="entra-connect" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#9729;</span> Entra Connect / Azure AD Connect</h2>
  <p class="section-desc">Detection of Entra ID (Azure AD) Connect sync service accounts in Active Directory.</p>
  $AADConnectTable
</div>

<!-- AD CERTIFICATE SERVICES -->
<div id="adcs" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(167,139,250,.15);color:var(--purple)">&#128272;</span> AD Certificate Services (ADCS)</h2>
  <p class="section-desc">Enterprise Certificate Authorities registered in Active Directory.</p>
  $ADCSTable
</div>

<!-- LAPS -->
<div id="laps" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(52,211,153,.15);color:var(--green)">&#128737;</span> LAPS Status</h2>
  <div class="info-grid">
    <div class="info-card"><span class="info-label">LAPS Deployed</span><span class="info-value">$(if($LAPSDeployed){'Yes'}else{'No'})</span></div>
    <div class="info-card"><span class="info-label">Type</span><span class="info-value">$LAPSType</span></div>
  </div>
</div>

<!-- AD HEALTH INDICATORS -->
<div id="ad-health" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(52,211,153,.15);color:var(--green)">&#9889;</span> AD Health Indicators</h2>
  <p class="section-desc">Quick reference for key AD health and security configuration items.</p>
  <div class="info-grid">
    <div class="info-card"><span class="info-label">AD Recycle Bin</span><span class="info-value">$(if($RecycleBinEnabled){'Enabled'}else{'NOT Enabled'})</span></div>
    <div class="info-card"><span class="info-label">BitLocker Keys in AD</span><span class="info-value">$(if($BitLockerKeysExist){'Yes -- recovery keys stored'}else{'None detected'})</span></div>
    <div class="info-card"><span class="info-label">LAPS Deployed</span><span class="info-value">$LAPSType</span></div>
    <div class="info-card"><span class="info-label">dMSA Schema Support</span><span class="info-value">$(if($dMSASupported){'Yes (Server 2025+)'}else{'No'})</span></div>
    <div class="info-card"><span class="info-label">Entra Connect</span><span class="info-value">$(if($AADConnectServers.Count -gt 0){"$($AADConnectServers.Count) service account(s) detected"}else{'Not detected'})</span></div>
    <div class="info-card"><span class="info-label">Enterprise CAs (ADCS)</span><span class="info-value">$(if($ADCSData.Count -gt 0){"$($ADCSData.Count) CA(s)"}else{'None detected'})</span></div>
    <div class="info-card"><span class="info-label">SYSVOL Replication</span><span class="info-value">$SysvolReplType</span></div>
    <div class="info-card"><span class="info-label">Tombstone Lifetime</span><span class="info-value">$TombstoneLife days</span></div>
    <div class="info-card"><span class="info-label">Schema Version</span><span class="info-value">$SchemaVersion ($SchemaOS)</span></div>
    <div class="info-card"><span class="info-label">DNS Forwarders</span><span class="info-value">$(if($DNSForwarders.Count -gt 0){$DNSForwarders -join ', '}else{'Not collected'})</span></div>
  </div>
</div>

<!-- OPTIONAL FEATURES -->
<div id="optional-features" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(34,211,238,.15);color:var(--accent2)">&#9881;</span> Optional Features</h2>
  $OptFeatTable
</div>

<!-- KERBEROS -->
<div id="kerberos" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128274;</span> Kerberos Policy</h2>
  <p class="section-desc">Default Kerberos settings from Default Domain Policy.</p>
  <div class="info-grid">
    <div class="info-card"><span class="info-label">Max TGT Lifetime</span><span class="info-value">$KerbMaxTicketAge</span></div>
    <div class="info-card"><span class="info-label">Max Renewal Lifetime</span><span class="info-value">$KerbMaxRenewAge</span></div>
    <div class="info-card"><span class="info-label">Max Service Ticket</span><span class="info-value">$KerbMaxServiceAge</span></div>
    <div class="info-card"><span class="info-label">Max Clock Skew</span><span class="info-value">$KerbMaxClockSkew</span></div>
  </div>
</div>

<!-- CHARTS -->
<div id="charts-overview" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128202;</span> Forest-Wide Component Charts</h2>
  <p class="section-desc">Aggregated percentage breakdown across all domains.</p>
  <div id="chartsContainer" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px;margin-bottom:20px"></div>
</div>

<!-- DIAGRAMS -->
<div id="diagrams" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(167,139,250,.15);color:var(--purple)">&#128506;</span> Infrastructure Diagrams</h2>
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px;margin-bottom:14px;box-shadow:var(--shadow)">
    <h3 style="font-size:.88rem;margin-bottom:12px;color:var(--text)">Forest FSMO Role Distribution</h3>
    <div id="fsmoDiagram"></div>
  </div>
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px;margin-bottom:14px;box-shadow:var(--shadow)">
    <h3 style="font-size:.88rem;margin-bottom:12px;color:var(--text)">DC Topology by Site</h3>
    <div id="dcDiagram"></div>
  </div>
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px;margin-bottom:14px;box-shadow:var(--shadow)">
    <h3 style="font-size:.88rem;margin-bottom:12px;color:var(--text)">Site Topology &amp; Replication Links</h3>
    <div id="siteDiagram"></div>
  </div>
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px;margin-bottom:14px;box-shadow:var(--shadow)">
    <h3 style="font-size:.88rem;margin-bottom:12px;color:var(--text)">Trust Relationships</h3>
    <div id="trustDiagram"></div>
  </div>
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px;margin-bottom:14px;box-shadow:var(--shadow);max-height:600px;overflow-y:auto">
    <h3 style="font-size:.88rem;margin-bottom:12px;color:var(--text)">OU Hierarchy (All Domains)</h3>
    <div id="ouDiagram"></div>
  </div>
</div>

<!-- FOOTER -->
<div class="footer">
  ADCanvas v2.0 -- Active Directory Documentation Report -- $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
  Developed by <a href="mailto:santhosh@sivarajan.com">Santhosh Sivarajan</a>, Microsoft MVP --
  <a href="https://github.com/SanthoshSivarajan/ADCanvas">github.com/SanthoshSivarajan/ADCanvas</a>
</div>

</main>
</div>

<script>
var userData=$UserChartJSON;
var compData=$CompChartJSON;
var groupData=$GroupChartJSON;
var gpoData=$GPOChartJSON;
var osDistData=$OSDistJSON;
var dcInfo=$DCInfoJSON;
var siteTopo=$SiteTopologyJSON;
var trustData=$TrustJSON;
var ouTree=$OUTreeJSON;
var domainDNS="$($Forest.Name)";
var schemaMaster="$($SchemaMaster -replace "'","")";
var namingMaster="$($NamingMaster -replace "'","")";
var COLORS=['#60a5fa','#34d399','#f87171','#fbbf24','#a78bfa','#f472b6','#22d3ee','#fb923c','#a3e635','#e879f9'];
var domainComp=$DomainCompJSON;
var dcSiteDist=$DCSiteDistStr;
var dcTypeData=$DCTypeJSON;
var privGroupData=$PrivGroupJSON;

function buildBarChart(t,d,c){var b=document.createElement('div');b.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;box-shadow:var(--shadow)';var h=document.createElement('h3');h.style.cssText='font-size:.86rem;margin-bottom:10px;color:#e2e8f0';h.textContent=t;b.appendChild(h);var tot=Object.values(d).reduce(function(a,b){return a+b},0);if(!tot){b.innerHTML+='<p style="color:#94a3b8;font-style:italic">No data.</p>';c.appendChild(b);return}var g=document.createElement('div');g.style.cssText='display:flex;flex-direction:column;gap:6px';var e=Object.entries(d),ci=0;for(var i=0;i<e.length;i++){var p=((e[i][1]/tot)*100).toFixed(1);var r=document.createElement('div');r.style.cssText='display:flex;align-items:center;gap:8px';r.innerHTML='<span style="width:100px;font-size:.74rem;color:#94a3b8;text-align:right;flex-shrink:0">'+e[i][0]+'</span><div style="flex:1;height:20px;background:#273548;border-radius:4px;overflow:hidden;border:1px solid #334155"><div style="height:100%;border-radius:3px;width:'+p+'%;background:'+COLORS[ci%COLORS.length]+';display:flex;align-items:center;padding:0 6px;font-size:.66rem;font-weight:600;color:#fff;white-space:nowrap">'+p+'%</div></div><span style="width:44px;font-size:.74rem;color:#94a3b8;text-align:right">'+e[i][1]+'</span>';g.appendChild(r);ci++}b.appendChild(g);c.appendChild(b)}

function buildDonut(t,d,c){var b=document.createElement('div');b.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;box-shadow:var(--shadow)';var h=document.createElement('h3');h.style.cssText='font-size:.86rem;margin-bottom:10px;color:#e2e8f0';h.textContent=t;b.appendChild(h);var tot=Object.values(d).reduce(function(a,b){return a+b},0);if(!tot){b.innerHTML+='<p style="color:#94a3b8;font-style:italic">No data.</p>';c.appendChild(b);return}var dc=document.createElement('div');dc.style.cssText='display:flex;align-items:center;gap:18px;flex-wrap:wrap';var sz=130,cx=65,cy=65,r=48,cf=2*Math.PI*r;var s='<svg width="'+sz+'" height="'+sz+'" viewBox="0 0 '+sz+' '+sz+'">';var off=0,ci=0,e=Object.entries(d);for(var i=0;i<e.length;i++){var pc=e[i][1]/tot,da=pc*cf,ga=cf-da;s+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+COLORS[ci%COLORS.length]+'" stroke-width="14" stroke-dasharray="'+da.toFixed(2)+' '+ga.toFixed(2)+'" stroke-dashoffset="'+(-off).toFixed(2)+'" transform="rotate(-90 '+cx+' '+cy+')" />';off+=da;ci++}s+='<text x="'+cx+'" y="'+cy+'" text-anchor="middle" dominant-baseline="central" fill="#e2e8f0" font-size="18" font-weight="700">'+tot+'</text></svg>';dc.innerHTML=s;var lg=document.createElement('div');lg.style.cssText='display:flex;flex-direction:column;gap:3px';ci=0;for(var i=0;i<e.length;i++){var pc=((e[i][1]/tot)*100).toFixed(1);var it=document.createElement('div');it.style.cssText='display:flex;align-items:center;gap:6px;font-size:.74rem;color:#94a3b8';it.innerHTML='<span style="width:10px;height:10px;border-radius:2px;background:'+COLORS[ci%COLORS.length]+';flex-shrink:0"></span>'+e[i][0]+': '+e[i][1]+' ('+pc+'%)';lg.appendChild(it);ci++}dc.appendChild(lg);b.appendChild(dc);c.appendChild(b)}

(function(){var c=document.getElementById('chartsContainer');if(!c)return;buildDonut('User Accounts (Forest)',userData,c);buildDonut('Computer Accounts (Forest)',compData,c);buildDonut('DC Type Distribution',dcTypeData,c);buildBarChart('DCs by Site',dcSiteDist,c);buildBarChart('Groups (Forest)',groupData,c);buildBarChart('GPO Status (Forest)',gpoData,c);if(osDistData&&osDistData.length){var o={};for(var i=0;i<osDistData.length;i++)o[osDistData[i].os]=osDistData[i].count;buildDonut('OS Distribution',o,c)}if(domainComp&&domainComp.length){var du={};for(var i=0;i<domainComp.length;i++)du[domainComp[i].domain]=domainComp[i].users;buildBarChart('Users by Domain',du,c);var dc={};for(var i=0;i<domainComp.length;i++)dc[domainComp[i].domain]=domainComp[i].computers;buildBarChart('Computers by Domain',dc,c);var dg={};for(var i=0;i<domainComp.length;i++)dg[domainComp[i].domain]=domainComp[i].dcs;buildBarChart('DCs by Domain',dg,c)}if(privGroupData&&privGroupData.length){var pg={};for(var i=0;i<privGroupData.length;i++)pg[privGroupData[i].name]=privGroupData[i].count;buildBarChart('Privileged Group Members (Top 15)',pg,c)}})();

function svgEl(t,a){var ns='http://www.w3.org/2000/svg',el=document.createElementNS(ns,t);for(var k in a)if(a.hasOwnProperty(k))el.setAttribute(k,a[k]);return el}
function svgText(x,y,t,o){var a={x:x,y:y,'text-anchor':'middle','dominant-baseline':'central','font-family':'Segoe UI,sans-serif',fill:'#e2e8f0'};for(var k in o)if(o.hasOwnProperty(k))a[k]=o[k];var el=svgEl('text',a);el.textContent=t;return el}
function svgRect(x,y,w,h,f,rx){return svgEl('rect',{x:x,y:y,width:w,height:h,fill:f||'#1e293b',rx:rx||6,stroke:'#334155','stroke-width':1})}

// FSMO Diagram
(function(){var roles=[{n:'Schema Master',h:schemaMaster},{n:'Domain Naming',h:namingMaster}];var holders={};for(var i=0;i<roles.length;i++){var h=roles[i].h.split('.')[0];if(!holders[h])holders[h]=[];holders[h].push(roles[i].n)}var hL=Object.entries(holders);var bW=200,rH=22,gap=40,pX=30;var dcY=90;var mR=Math.max.apply(null,hL.map(function(h){return h[1].length}));var dbH=36+mR*rH;var tW=hL.length*(bW+gap)-gap+pX*2;var tH=dcY+dbH+30;var s=svgEl('svg',{viewBox:'0 0 '+tW+' '+tH,width:Math.min(tW,800),xmlns:'http://www.w3.org/2000/svg'});s.appendChild(svgRect(30,20,tW-60,40,'#273548'));s.appendChild(svgText(tW/2,40,'Forest: '+domainDNS,{'font-size':'13','font-weight':'700',fill:'#60a5fa'}));for(var i=0;i<hL.length;i++){var dc=hL[i][0],rl=hL[i][1];var x=pX+i*(bW+gap);var bH=36+rl.length*rH;s.appendChild(svgEl('line',{x1:tW/2,y1:60,x2:x+bW/2,y2:dcY,stroke:'#334155','stroke-width':1.5,'stroke-dasharray':'4 3'}));s.appendChild(svgRect(x,dcY,bW,bH,'#1e293b'));s.appendChild(svgText(x+bW/2,dcY+16,dc,{'font-size':'12','font-weight':'700',fill:'#34d399'}));for(var ri=0;ri<rl.length;ri++){s.appendChild(svgRect(x+10,dcY+32+ri*rH,bW-20,rH-4,'#273548',4));s.appendChild(svgText(x+bW/2,dcY+32+ri*rH+(rH-4)/2,rl[ri],{'font-size':'10',fill:'#a78bfa'}))}}document.getElementById('fsmoDiagram').appendChild(s)})();

// DC Topology
(function(){if(!dcInfo||!dcInfo.length)return;var bS={};for(var i=0;i<dcInfo.length;i++){var s=dcInfo[i].site||'Unknown';if(!bS[s])bS[s]=[];bS[s].push(dcInfo[i])}var sN=Object.keys(bS);var sW=260,sG=28,dH=66,pX=28,pY=18;var mD=Math.max.apply(null,sN.map(function(s){return bS[s].length}));var sH=48+mD*(dH+6)+10;var tW=sN.length*(sW+sG)-sG+pX*2;var tH=sH+pY*2+30;var sv=svgEl('svg',{viewBox:'0 0 '+tW+' '+tH,width:Math.min(tW,950),xmlns:'http://www.w3.org/2000/svg'});for(var si=0;si<sN.length;si++){var st=sN[si];var x=pX+si*(sW+sG),y=pY;sv.appendChild(svgRect(x,y,sW,sH,'#152033'));sv.appendChild(svgText(x+sW/2,y+18,'Site: '+st,{'font-size':'11','font-weight':'700',fill:'#22d3ee'}));var dcs=bS[st];for(var di=0;di<dcs.length;di++){var dc=dcs[di];var dy=y+38+di*(dH+6);var fl=dc.rodc?'#422006':'#1e293b';sv.appendChild(svgRect(x+10,dy,sW-20,dH,fl));sv.appendChild(svgText(x+sW/2,dy+12,dc.name,{'font-size':'10','font-weight':'700',fill:'#e2e8f0'}));sv.appendChild(svgText(x+sW/2,dy+26,(dc.ip||'')+' | '+(dc.os||'').replace('Windows Server ','WS'),{'font-size':'8',fill:'#94a3b8'}));if(dc.osver)sv.appendChild(svgText(x+sW/2,dy+38,'Build: '+dc.osver+' | '+dc.domain,{'font-size':'7',fill:'#94a3b8'}));var bd=[];if(dc.gc)bd.push('GC');if(dc.rodc)bd.push('RODC');else bd.push('RWDC');if(bd.length)sv.appendChild(svgText(x+sW/2,dy+52,bd.join(' | '),{'font-size':'8',fill:'#fbbf24','font-weight':'600'}))}}document.getElementById('dcDiagram').appendChild(sv)})();

// Site Topology
(function(){if(!siteTopo||!siteTopo.sites||!siteTopo.sites.length)return;var si=siteTopo.sites,lk=siteTopo.sitelinks||[],su=siteTopo.subnets||[];var nW=160,nH=70,pX=60,pY=50;var co=Math.min(si.length,4),ro=Math.ceil(si.length/co);var gX=80,gY=100;var tW=co*(nW+gX)-gX+pX*2,tH=ro*(nH+gY)-gY+pY*2+30;var sv=svgEl('svg',{viewBox:'0 0 '+tW+' '+tH,width:Math.min(tW,900),xmlns:'http://www.w3.org/2000/svg'});var po={};for(var i=0;i<si.length;i++){var c=i%co,r=Math.floor(i/co);po[si[i].name]={x:pX+c*(nW+gX)+nW/2,y:pY+r*(nH+gY)+nH/2}}for(var li=0;li<lk.length;li++){var l=lk[li],ls=l.sites||[];for(var i=0;i<ls.length;i++){for(var j=i+1;j<ls.length;j++){var sA=(ls[i]+'').replace(/^CN=([^,]+).*/,'$1'),sB=(ls[j]+'').replace(/^CN=([^,]+).*/,'$1');if(po[sA]&&po[sB]){sv.appendChild(svgEl('line',{x1:po[sA].x,y1:po[sA].y,x2:po[sB].x,y2:po[sB].y,stroke:'#60a5fa','stroke-width':2,'stroke-dasharray':'6 3'}));var mx=(po[sA].x+po[sB].x)/2,my=(po[sA].y+po[sB].y)/2;sv.appendChild(svgText(mx,my-8,l.name,{'font-size':'8',fill:'#94a3b8'}));sv.appendChild(svgText(mx,my+4,'Cost:'+l.cost+' Freq:'+l.freq+'m',{'font-size':'7',fill:'#64748b'}))}}}}for(var i=0;i<si.length;i++){var s=si[i],p=po[s.name];if(!p)continue;sv.appendChild(svgRect(p.x-nW/2,p.y-nH/2,nW,nH,'#1e293b'));sv.appendChild(svgText(p.x,p.y-8,s.name,{'font-size':'12','font-weight':'700',fill:'#22d3ee'}));var sc=su.filter(function(sub){return(sub.site+'').indexOf(s.name)!==-1}).length;sv.appendChild(svgText(p.x,p.y+10,sc+' subnet(s)',{'font-size':'9',fill:'#94a3b8'}))}document.getElementById('siteDiagram').appendChild(sv)})();

// Trust Diagram
(function(){if(!trustData||!trustData.length){document.getElementById('trustDiagram').innerHTML='<p style="color:#94a3b8;font-style:italic">No trusts configured.</p>';return}var pX=60,pY=40,bW=200,bH=50,gap=100;var tW=Math.max(trustData.length*(bW+gap)+pX*2,500),tH=240;var sv=svgEl('svg',{viewBox:'0 0 '+tW+' '+tH,width:Math.min(tW,900),xmlns:'http://www.w3.org/2000/svg'});var df=svgEl('defs');var ps=[['aG','#34d399'],['aA','#fbbf24']];for(var p=0;p<ps.length;p++){var mk=svgEl('marker',{id:ps[p][0],viewBox:'0 0 10 10',refX:10,refY:5,markerWidth:6,markerHeight:6,orient:'auto-start-reverse'});mk.appendChild(svgEl('path',{d:'M0,0 L10,5 L0,10 Z',fill:ps[p][1]}));df.appendChild(mk)}sv.insertBefore(df,sv.firstChild);var tx=tW/2,ty=pY+25;sv.appendChild(svgRect(tx-bW/2,pY,bW,bH,'#273548'));sv.appendChild(svgText(tx,ty,domainDNS,{'font-size':'12','font-weight':'700',fill:'#60a5fa'}));for(var i=0;i<trustData.length;i++){var t=trustData[i];var cx=pX+i*(bW+gap)+bW/2,cy=tH-pY-bH/2;sv.appendChild(svgRect(cx-bW/2,cy-bH/2,bW,bH,'#1e293b'));sv.appendChild(svgText(cx,cy-8,t.name,{'font-size':'11','font-weight':'600',fill:'#f472b6'}));sv.appendChild(svgText(cx,cy+8,t.type+' ('+t.direction+')',{'font-size':'9',fill:'#94a3b8'}));var dr=(t.direction+'').toLowerCase();var mx=(tx+cx)/2,my=(ty+25+cy-bH/2)/2;if(dr==='bidirectional'||dr==='2')sv.appendChild(svgEl('line',{x1:tx,y1:ty+25,x2:cx,y2:cy-bH/2,stroke:'#34d399','stroke-width':2,'marker-end':'url(#aG)','marker-start':'url(#aG)'}));else sv.appendChild(svgEl('line',{x1:tx,y1:ty+25,x2:cx,y2:cy-bH/2,stroke:'#fbbf24','stroke-width':2,'marker-end':'url(#aA)'}));sv.appendChild(svgText(mx,my,t.transitive?'Transitive':'Non-Trans.',{'font-size':'8',fill:'#64748b'}))}document.getElementById('trustDiagram').appendChild(sv)})();

// OU Tree
(function(){if(!ouTree||!ouTree.length){document.getElementById('ouDiagram').innerHTML='<p style="color:#94a3b8;font-style:italic">No OUs.</p>';return}var c=document.getElementById('ouDiagram');var l=document.createElement('div');l.style.cssText='font-size:12px;line-height:1.8;font-family:Cascadia Code,Fira Code,monospace';var curDom='';var sorted=ouTree.slice().sort(function(a,b){if(a.domain!==b.domain)return a.domain.localeCompare(b.domain);return a.depth-b.depth||a.name.localeCompare(b.name)});for(var i=0;i<sorted.length;i++){var ou=sorted[i];if(ou.domain!==curDom){curDom=ou.domain;var dh=document.createElement('div');dh.style.cssText='color:#60a5fa;font-weight:700;margin-top:10px;font-size:13px;border-bottom:1px solid #334155;padding-bottom:2px;margin-bottom:4px';dh.textContent='Domain: '+curDom;l.appendChild(dh)}var ln=document.createElement('div');ln.style.paddingLeft=(ou.depth*22+6)+'px';var pi=ou.prot?'<span style="color:#34d399" title="Protected">&#128274;</span>':'<span style="color:#f87171" title="NOT protected">&#128275;</span>';var tc=ou.depth>0?'<span style="color:#475569">&#9492;&#9472; </span>':'';ln.innerHTML=tc+'<span style="color:#fbbf24">&#128193;</span> <span style="color:#e2e8f0">'+ou.name+'</span> '+pi;l.appendChild(ln)}c.appendChild(l)})();

// Sidebar scroll tracking
(function(){var lk=document.querySelectorAll('.sidebar nav a');var sc=[];for(var i=0;i<lk.length;i++){var id=lk[i].getAttribute('href');if(id&&id.charAt(0)==='#'){var el=document.querySelector(id);if(el)sc.push({el:el,link:lk[i]})}}window.addEventListener('scroll',function(){var cur=sc[0];for(var i=0;i<sc.length;i++){if(sc[i].el.getBoundingClientRect().top<=120)cur=sc[i]}for(var i=0;i<lk.length;i++)lk[i].classList.remove('active');if(cur)cur.link.classList.add('active')})})();
</script>
</body>
</html>
<!--
================================================================================
  ADCanvas -- Active Directory Documentation Report
  Author : Santhosh Sivarajan, Microsoft MVP
  Email  : santhosh@sivarajan.com
================================================================================
-->
"@

# --- Write Report -------------------------------------------------------------
$HTML | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
$FileSize = [math]::Round((Get-Item $OutputFile).Length / 1KB, 1)

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host "  |   ADCanvas -- Report Generation Complete                   |" -ForegroundColor Green
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  FOREST SUMMARY" -ForegroundColor White
Write-Host "  --------------" -ForegroundColor Gray
Write-Host "    Domains            : $($ForestDomains.Count) ($(($ForestDomains | ForEach-Object {[string]$_}) -join ', '))" -ForegroundColor White
Write-Host "    Domain Controllers : $($AllForestDCs.Count) (RWDC: $(@($AllForestDCs | Where-Object {$_.Type -eq 'RWDC'}).Count), RODC: $(@($AllForestDCs | Where-Object {$_.Type -eq 'RODC'}).Count))" -ForegroundColor White
Write-Host "    AD Sites           : $($ADSites.Count)" -ForegroundColor White
Write-Host "    Trusts             : $($AllTrusts.Count)" -ForegroundColor White
Write-Host "    Total Users        : $ForestTotalUsers" -ForegroundColor White
Write-Host "    Total Computers    : $ForestTotalComputers" -ForegroundColor White
Write-Host "    Total Groups       : $ForestTotalGroups" -ForegroundColor White
Write-Host "    Total GPOs         : $ForestTotalGPOs" -ForegroundColor White
Write-Host "    Entra Connect      : $(if($AADConnectServers.Count -gt 0){"$($AADConnectServers.Count) detected"}else{'Not detected'})" -ForegroundColor White
Write-Host "    ADCS (CAs)         : $(if($ADCSData.Count -gt 0){"$($ADCSData.Count) CA(s)"}else{'None'})" -ForegroundColor White
Write-Host "    LAPS               : $LAPSType" -ForegroundColor White
Write-Host "    Recycle Bin        : $(if($RecycleBinEnabled){'Enabled'}else{'Not Enabled'})" -ForegroundColor White
Write-Host ""
Write-Host "  OUTPUT" -ForegroundColor White
Write-Host "  ------" -ForegroundColor Gray
Write-Host "    Report File : $OutputFile" -ForegroundColor White
Write-Host "    File Size   : $FileSize KB" -ForegroundColor White
Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |  This report was generated using ADCanvas v2.0             |" -ForegroundColor Cyan
Write-Host "  |  Developed by Santhosh Sivarajan, Microsoft MVP            |" -ForegroundColor Cyan
Write-Host "  |  santhosh@sivarajan.com                                    |" -ForegroundColor Cyan
Write-Host "  |  https://github.com/SanthoshSivarajan/ADCanvas             |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""

<#
================================================================================
  ADCanvas v2.0 -- Active Directory Documentation Report Generator
  Author : Santhosh Sivarajan, Microsoft MVP
  Email  : santhosh@sivarajan.com
  GitHub : https://github.com/SanthoshSivarajan/ADCanvas
================================================================================
#>
