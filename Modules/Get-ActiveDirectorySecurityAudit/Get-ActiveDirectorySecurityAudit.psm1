# Function to determine if Powershell is running interactively.
function Get-IfInteractiveShell {
    # Test each Arg for match of abbreviated '-NonInteractive' command.
    $NonInteractive = [Environment]::GetCommandLineArgs() | Where-Object{ $_ -like '-NonI*' }

    if ([Environment]::UserInteractive -and -not $NonInteractive) {
        # We are in an interactive shell.
        return $true
    }

    return $false
}

# A Translation function to allow cross Domain lookup
function Translate-DNtoDomainName {
    param (
        [Parameter(Mandatory)]
        [string]
        $DistinguishedName
    )
    $Domain = (($DistinguishedName -split ",") -match "DC=") -replace "DC=" -join "."
    Return $Domain
}

# Function to audit Organizational Units
function Audit-OUs {
    param (
        [string[]]$AdditionalOUs,
        [string]$Server
    )
    If($Server){
        $Domain = Get-ADDomain $Server
    }Else{
        $Domain = Get-ADDomain -Current LocalComputer
    }
    $DefaultOUs = Get-ADObject -SearchBase $($Domain.DistinguishedName) -SearchScope OneLevel -Filter * -Server $($Domain.DNSRoot) | Where-Object -Property DistinguishedName -Like "*CN=*" | Select-Object -ExpandProperty DistinguishedName
    $allOUs = $defaultOUs + $AdditionalOUs
    $PropertyArray = @(
        "Name",
        "DistinguishedName",
        "Enabled",
        "Description",
        "WhenCreated",
        "WhenChanged",
        "ObjectClass",
        "PasswordLastSet"
    )
    $result = @()
    $Script:PrivilegedGroups = @()
    foreach ($ou in $allOUs) {
        If(($ou -ne $null) -and ($ou -ne "CN=Microsoft Exchange System Objects,$($Domain.DistinguishedName)") -and ($ou -ne "CN=QuestReplicationMonitoring,$($Domain.DistinguishedName)")){
            Get-ADObject -SearchBase $ou -Filter * -SearchScope Subtree -Server $($Domain.DNSRoot) | Where-Object -Property DistinguishedName -NE $ou | ForEach-Object {
                $DistinguishedName = $_.DistinguishedName
                
                switch($_.ObjectClass){
                    computer { $info = Get-ADComputer -Identity $DistinguishedName -Properties $PropertyArray -Server (Translate-DNtoDomainName $DistinguishedName) }
                    user { $info = Get-ADUser -Identity $DistinguishedName -Properties $PropertyArray -Server (Translate-DNtoDomainName $DistinguishedName) }
                    group { $info = $null ; $Script:PrivilegedGroups += $DistinguishedName }
                    Default {$info = $null}
                }
                If($Info){
                    if(($info.SamAccountName -notin $result.SamAccountName)){
                        $result += [PScustomObject]@{
                            Name = $Info.Name
                            ObjectClass = ($Info.ObjectClass).ToString()
                            PublishedAt = ($info.DistinguishedName).Replace("CN=$($Info.Name),",'')
                            Enabled = $Info.Enabled
                            SamAccountName = $Info.SamAccountName
                            PasswordLastSet = $Info.PasswordLastSet
                            WhenCreated = $Info.WhenCreated
                            WhenChanged = $Info.WhenChanged
                            Description = $Info.Description
                        }
                        If( ($info.Name -like "*$") -And ($info.ObjectClass -eq 'User') ){
                            $Result[-1].ObjectClass = "Trust"
                        }
                    }
                }
            }
        }
    }
    return $result
}

# Function to audit privileged groups
function Audit-PrivilegedGroups {
    param (
        [string[]]$AdditionalGroups,
        [string]$Server
    )
    If($Server){
        $Domain = Get-ADDomain $Server
    }Else{
        $Domain = Get-ADDomain -Current LocalComputer
    }
    $defaultGroups = Get-ADGroup -SearchBase "CN=Builtin,$($Domain.DistinguishedName)" -Filter * -Server $($Domain.DNSRoot) | Select-Object -ExpandProperty DistinguishedName
    $allGroups = ($defaultGroups + $Script:PrivilegedGroups + $AdditionalGroups | Sort-Object -Unique)

    $Groupresult = @()
    foreach ($group in $allGroups) {
        If(($group -ne "CN=Domain Users,CN=Users,$($Domain.DistinguishedName)") -and ($group -ne "CN=Domain Computers,CN=Users,$($Domain.DistinguishedName)")){
            $groupInfo = Get-ADGroup -Identity $group -Properties Description, WhenCreated, WhenChanged -Server (Translate-DNtoDomainName $group) -ErrorAction SilentlyContinue
            $members = @()
            if ($groupInfo) {
                Get-ADGroup -Identity $group -Server (Translate-DNtoDomainName $group) -Properties Members -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Members | ForEach-Object {$Name = Get-ADUser -Identity $_ -Server (Translate-DNtoDomainName $_) | Select-Object -ExpandProperty SamAccountName; If($Null -ne $Name){$DLName = (Translate-DNtoDomainName $_) + '\' + $Name; $members += $DLName; $DLName = $null; $Name = $Null} }
                if($members){
                    $Groupresult += [PSCustomObject]@{
                        GroupName = $group
                        Members = $members
                    }
                }
            }
        }
    }
    return $Groupresult
}

# Function to Audit Trusts
function Audit-Trusts {
    Param (
        [string]$Server
    )
    If($Server){
        $Domain = Get-ADDomain $Server
    }Else{
        $Domain = Get-ADDomain -Current LocalComputer
    }
    
    Get-ADTrust -Filter * -Server $($Domain.DNSRoot)| Select-Object -Property Name, Direction, ForestTransitive, IsTreeParent, IsTreeRoot, Source, Target, TrustType, UsesAesKeys, UsesRC4Encryption
}

# Function to export Fine-Grained Password Policies
function Export-FineGrainedPasswordPolicies {
    Param (
        [string]$Server
    )
    If($Server){
        $Domain = Get-ADDomain $Server
    }Else{
        $Domain = Get-ADDomain -Current LocalComputer
    }
    Get-ADFineGrainedPasswordPolicy -Filter * -Server $($Domain.DNSRoot)| Select-Object Name, Precedence, MinPasswordLength, LockoutDuration, LockoutObservationWindow, LockoutThreshold, MaxPasswordAge, MinPasswordAge, PasswordHistoryCount, ReversibleEncryptionEnabled, ComplexityEnabled
}

# Function to Audit Kerberos Policies from the Default Domain Policy GPO and Default Password Policy
function Audit-KerberosPolicies {
    Param (
        [string]$Server
    )
    If($Server){
        $Domain = Get-ADDomain $Server
    }Else{
        $Domain = Get-ADDomain -Current LocalComputer
    }

    $DefaultPasswordPolicy = Get-ADDefaultDomainPasswordPolicy -Server $($Domain.DNSRoot) | Select-Object MinPasswordLength, LockoutDuration, LockoutObservationWindow, LockoutThreshold, MaxPasswordAge, MinPasswordAge, PasswordHistoryCount, ReversibleEncryptionEnabled, ComplexityEnabled    
    $DefaultDomainGPO = Get-GPInheritance -Domain $($Domain.DNSRoot) -Target $($Domain.DistinguishedName) | Select-Object -ExpandProperty GPOLinks | Where-Object -Property DisplayName -Like "*fault Domain Poli*"
    
    # Kerberos Policies from Default Domain GPO
    $GPOReportXml = Get-GPOReport -Guid $DefaultDomainGPO.GPOId -ReportType Xml -Domain $($Domain.DNSRoot)
    $GPOReportXmlObject = [xml]$GPOReportXml
    $KerberosPolicies = ($GPOReportXmlObject.GPO.Computer.ExtensionData | Where-Object -Property Name -EQ "Security").Extension.Account

    $KerberosPolicyData = [PSCustomObject]@{
        PasswordHistoryCount = $DefaultPasswordPolicy.PasswordHistoryCount 
        MaxPasswordAge = $DefaultPasswordPolicy.MaxPasswordAge 
        MinPasswordAge = $DefaultPasswordPolicy.MinPasswordAge 
        MinPasswordLength = $DefaultPasswordPolicy.MinPasswordLength 
        ComplexityEnabled = $DefaultPasswordPolicy.ComplexityEnabled
        ReversibleEncryptionEnabled = $DefaultPasswordPolicy.ReversibleEncryptionEnabled
        LockoutDuration = $DefaultPasswordPolicy.LockoutDuration 
        LockoutThreshold = $DefaultPasswordPolicy.LockoutThreshold 
        LockoutObservationWindow = $DefaultPasswordPolicy.LockoutObservationWindow 
        UserLogonRestrictionsEnabled = ($KerberosPolicies | Where-Object -Property Name -EQ "TicketValidateClient" | Select-Object -Property SettingBoolean).SettingBoolean
        ServiceTicketLifetime = ($KerberosPolicies | Where-Object -Property Name -EQ "MaxServiceAge").SettingNumber
        UserTicketLifetime = ($KerberosPolicies | Where-Object -Property Name -EQ "MaxTicketAge").SettingNumber
        UserTicketRenewalLifetime = ($KerberosPolicies | Where-Object -Property Name -EQ "MaxRenewAge").SettingNumber
        ClockSynchronizationTolerance = ($KerberosPolicies | Where-Object -Property Name -EQ "MaxClockSkew").SettingNumber
    }

    Return $KerberosPolicyData
}

# Entire Audit Function wrapped up to display outputs. Variables should be accessible after the function runs if running manually.
function Get-ActiveDirectorySecurityAudit {
    Param (
        [string]$Server
    )
    # Import the Active Directory module
    Import-Module ActiveDirectory
    # Define a domain object
    If($Server){
        $Domain = Get-ADDomain $Server
    }Else{
        $Domain = Get-ADDomain -Current LocalComputer
    }



    # Audit OUs
    $Global:ouAudit = Audit-OUs -Server $($Domain.DNSRoot)
    #$ouAudit = Audit-OUs -AdditionalOUs "CN="HR,DC=Contoso,DC=Com", "CN=IT,DC=Contoso,DC=Com"
    
    # Audit Privileged Groups
    $Global:privilegedGroupsAudit = Audit-PrivilegedGroups -Server $($Domain.DNSRoot)
    #$privilegedGroupsAudit = Audit-PrivilegedGroups $($Domain.DNSRoot) -AdditionalGroups "CN=AdminGroup,OU=RBAC,OU=Groups,DC=Contoso,DC=com", "CN=DesktopSupport,OU=RBAC,OU=Groups,DC=Contoso,DC=com"
    
    # Audit Domain Trusts
    $Global:Trusts = Audit-Trusts -Server $($Domain.DNSRoot)

    # Export Password Policies
    $Global:fineGrainedPolicies = Export-FineGrainedPasswordPolicies -Server $($Domain.DNSRoot)
    $Global:defaultPasswordPolicy = Audit-KerberosPolicies -Server ($Domain.DNSRoot)
    
    # Output results
    $Global:ouAudit | Out-GridView
    $Global:privilegedGroupsAudit | Out-GridView
    $Global:Trusts | Out-GridView
    Write-Host "Default Password Policy" -ForegroundColor Yellow
    $Global:defaultPasswordPolicy
    Write-Host "`nFine Grained Password Policies" -ForegroundColor Yellow
    $Global:fineGrainedPolicies 


    Write-Host "`n`n`nAudit is complete use the following variables to view or export the results:" -ForegroundColor Green
    Write-Host '$ouAudit, $privilegedGroupsAudit, $fineGrainedPolicies, $defaultPasswordPolicy, $Trusts' -ForegroundColo Yellow
}

Export-ModuleMember Get-ActiveDirectorySecurityAudit