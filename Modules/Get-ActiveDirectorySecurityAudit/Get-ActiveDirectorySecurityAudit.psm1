# Function to audit Organizational Units
function Audit-OUs {
    param (
        [string[]]$AdditionalOUs
    )

    $DomainDN = (Get-ADDomain -Current LocalComputer).DistinguishedName
    $DefaultOUs = Get-ADObject -SearchBase $DomainDN -SearchScope OneLevel -Filter * | Where-Object -Property DistinguishedName -Like "*CN=*" | Select-Object -ExpandProperty DistinguishedName
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
        If($ou -ne $null){
            Get-ADObject -SearchBase $ou -Filter * -SearchScope Subtree | Where-Object -Property DistinguishedName -NE $ou | ForEach-Object {
                $DistinguishedName = $_.DistinguishedName
                
                switch($_.ObjectClass){
                    computer { $info = Get-ADComputer -Identity $DistinguishedName -Properties $PropertyArray }
                    user { $info = Get-ADUser -Identity $DistinguishedName -Properties $PropertyArray }
                    group { $info = $null ; $Script:PrivilegedGroups += $DistinguishedName }
                    Default {$info = $null}
                }
                If($Info){
                    if($info.SamAccountName -notin $result.SamAccountName){
                        $result += [PScustomObject]@{
                            Name = $Info.Name
                            ObjectClass = $Info.ObjectClass
                            PublishedAt = ($info.DistinguishedName).Replace("CN=$($Info.Name),",'')
                            Enabled = $Info.Enabled
                            SamAccountName = $Info.SamAccountName
                            PasswordLastSet = $Info.PasswordLastSet
                            WhenCreated = $Info.WhenCreated
                            WhenChanged = $Info.WhenChanged
                            Description = $Info.Description
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
        [string[]]$AdditionalGroups
    )
    $DomainDN = (Get-ADDomain -Current LocalComputer).DistinguishedName
    $defaultGroups = Get-ADGroup -SearchBase "CN=Builtin,$DomainDN" -Filter * | Select-Object -ExpandProperty DistinguishedName
    $allGroups = ($defaultGroups + $Script:PrivilegedGroups + $AdditionalGroups | Sort-Object -Unique)

    $Groupresult = @()
    foreach ($group in $allGroups) {
        If(($group -ne "CN=Domain Users,CN=Users,$DomainDN") -and ($group -ne "CN=Domain Computers,CN=Users,$DomainDN")){
            $groupInfo = Get-ADGroup -Identity $group -Properties Description, WhenCreated, WhenChanged -ErrorAction SilentlyContinue
            if ($groupInfo) {
                $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
                $Groupresult += [PSCustomObject]@{
                    GroupName = $group
                    Members = $members
                }
            }
        }
    }
    return $Groupresult
}

# Function to export Fine-Grained Password Policies
function Export-FineGrainedPasswordPolicies {
    Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name, Precedence, MinPasswordLength, LockoutDuration, LockoutObservationWindow, LockoutThreshold, MaxPasswordAge, MinPasswordAge, PasswordHistoryCount, ReversibleEncryptionEnabled, ComplexityEnabled
}

# Function to export Default Password Policy
function Export-DefaultPasswordPolicy {
    Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength, LockoutDuration, LockoutObservationWindow, LockoutThreshold, MaxPasswordAge, MinPasswordAge, PasswordHistoryCount, ReversibleEncryptionEnabled, ComplexityEnabled
}

# Entire Audit Function wrapped up to display outputs. Variables should be accessible after the function runs if running manually.
Function Get-ActiveDirectorySecurityAudit {
    # Import the Active Directory module
    Import-Module ActiveDirectory

    # Audit OUs
    $Global:ouAudit = Audit-OUs 
    #$ouAudit = Audit-OUs -AdditionalOUs "HR", "IT"
    
    # Audit Privileged Groups
    $Global:privilegedGroupsAudit = Audit-PrivilegedGroups
    #$privilegedGroupsAudit = Audit-PrivilegedGroups -AdditionalGroups @("Backup Operators", "Print Operators")
    
    # Export Password Policies
    $Global:fineGrainedPolicies = Export-FineGrainedPasswordPolicies
    $Global:defaultPasswordPolicy = Export-DefaultPasswordPolicy
    
    # Output results
    $Global:ouAudit | Format-Table
    $Global:privilegedGroupsAudit | Format-Table
    $Global:fineGrainedPolicies | Format-Table
    $Global:defaultPasswordPolicy | Format-Table

    Write-Host "Audit is complete use the following variables to view or export the results:" -ForegroundColor Green
    Write-Host '$ouAudit, $privilegedGroupsAudit, $fineGrainedPolicies, $defaultPasswordPolicy' -ForegroundColo Yellow
}

Export-ModuleMember Get-ActiveDirectorySecurityAudit