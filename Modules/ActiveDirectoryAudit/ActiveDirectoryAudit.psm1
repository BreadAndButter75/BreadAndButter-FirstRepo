Function Translate-DNToOU {
    param(
        [parameter(Mandatory)]
        [string]$DistinguishedName
    )

    Try {
        $OrganizationalUnit = $DistinguishedName
        While(($OrganizationalUnit -notlike "OU=*") -and ($OrganizationalUnit -notlike "CN=Builtin,*") -and ($OrganizationalUnit -notlike "CN=Microsoft Exchange System Objects,*") -and ($OrganizationalUnit -notlike "CN=Computers,*") -and ($OrganizationalUnit -notlike "ForeignSecurityPrincipals,*") -and ($OrganizationalUnit -notlike "CN=LostAndFound,*") -and ($OrganizationalUnit -notlike "CN=Managed Service Accounts,*") -and ($OrganizationalUnit -notlike "CN=OpsMgrLatencyMonitors,*") -and ($OrganizationalUnit -notlike "CN=Program Data,*") -and ($OrganizationalUnit -notlike "CN=QuestReplicationMonitoring,*") -and ($OrganizationalUnit -notlike "CN=System,*") -and ($OrganizationalUnit -notlike "CN=Unity,*") -and ($OrganizationalUnit -notlike "CN=Users,*") -and ($OrganizationalUnit -notlike "CN=NTDS Quotas,*") -and ($OrganizationalUnit -notlike "CN=TPM Devices")){
            $OrganizationalUnit = $OrganizationalUnit.Replace($OrganizationalUnit.Split(',')[0] + ',','')
        }
        return $OrganizationalUnit
    }
    Catch {
        Write-Host "An Error has occured in " -ForegroundColor Red -NoNewLine
        Write-Host "Translate-DNToOU" -ForegroundColor Yellow
        Write-Host $Error    
    }

}
Function Get-OUsWithUsers {
    Param (
        [Parameter()]
        [string]$Domain
    )

    $Global:OUHash = @{}
    If($Domain){
        $Params = @{
            'Filter' = '*'
            'Server' = $Domain
        }
    }Else{
        $Params = @{
            'Filter' = '*'
        }
    }
    Get-ADUser @Params | Foreach-Object {
        Write-Host $_.SamAccountName -ForegroundColor Yellow
        $OUName = Translate-DNToOU $_.DistinguishedName
        If($OUHash.ContainsKey($OUName)){
            ($OUHash.$OUName)++
        }ElseIf(!($OUHash.ContainsKey($OUName))){
            $OUHash.Add($OUName,1)
        }
    }
    return $Global:OUHash
}

Export-ModuleMember Translate-DNtoOU
Export-ModuleMember Get-OUsWithUsers
