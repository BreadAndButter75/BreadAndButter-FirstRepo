# Import the Active Directory module
Import-Module ActiveDirectory

# Function to audit Organizational Units
function Audit-OUs {
    param (
        [string[]]$AdditionalOUs
    )
    $defaultOUs = "Computers", "Users", "Builtin"
    $allOUs = $defaultOUs + $AdditionalOUs

    $result = @()
    foreach ($ou in $allOUs) {
        $ouInfo = Get-ADOrganizationalUnit -Filter "Name -like '*$ou*'" -ErrorAction SilentlyContinue
        if ($ouInfo) {
            $result += $ouInfo | Select-Object Name, DistinguishedName
        }
    }
    return $result
}

# Function to audit privileged groups
function Audit-PrivilegedGroups {
    param (
        [string[]]$AdditionalGroups
    )
    $defaultGroups = "Domain Admins", "Schema Admins", "Enterprise Admins", "Administrators"
    $allGroups = $defaultGroups + $AdditionalGroups

    $result = @()
    foreach ($group in $allGroups) {
        $groupInfo = Get-ADGroup -Identity $group -ErrorAction SilentlyContinue
        if ($groupInfo) {
            $members = Get-ADGroupMember -Identity $group -Recursive | Select-Object Name, SamAccountName, DistinguishedName
            $result += [PSCustomObject]@{
                GroupName = $group
                Members = $members
            }
        }
    }
    return $result
}

# Function to export Fine-Grained Password Policies
function Export-FineGrainedPasswordPolicies {
    Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name, Precedence, MinPasswordLength, LockoutDuration, LockoutObservationWindow, LockoutThreshold, MaxPasswordAge, MinPasswordAge, PasswordHistoryCount, ReversibleEncryptionEnabled, ComplexityEnabled
}

# Function to export Default Password Policy
function Export-DefaultPasswordPolicy {
    Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength, LockoutDuration, LockoutObservationWindow, LockoutThreshold, MaxPasswordAge, MinPasswordAge, PasswordHistoryCount, ReversibleEncryptionEnabled, ComplexityEnabled
}

# Main script execution
Write-Host "Starting AD Domain Audit..."

# Audit OUs
$ouAudit = Audit-OUs 
#$ouAudit = Audit-OUs -AdditionalOUs "HR", "IT"

# Audit Privileged Groups
$privilegedGroupsAudit = Audit-PrivilegedGroups
#$privilegedGroupsAudit = Audit-PrivilegedGroups -AdditionalGroups @("Backup Operators", "Print Operators")

# Export Password Policies
$fineGrainedPolicies = Export-FineGrainedPasswordPolicies
$defaultPasswordPolicy = Export-DefaultPasswordPolicy

# Output results
$ouAudit | Format-Table -AutoSize

$privilegedGroupsAudit | ForEach-Object {
    Write-Host "Group: $_.GroupName"
    $_.Members | Format-Table -AutoSize
}

$fineGrainedPolicies | Format-Table -AutoSize
$defaultPasswordPolicy | Format-Table -AutoSize

Write-Host "AD Domain Audit Completed."