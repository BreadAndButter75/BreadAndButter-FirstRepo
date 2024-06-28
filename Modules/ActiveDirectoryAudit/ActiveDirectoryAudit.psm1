Function Translate-DNToOU {
    param(
        [parameter(Mandatory)]
        [string]$DistinguishedName
    )

    Try {
        If($DistinguishedName -Like "OU=*"){
            $OrganizationalUnit = $DistinguishedName
        }Else{
            $OrganizationalUnit = $DistinguishedName.Replace($DistinguishedName.Split(',')[0] + ',','')
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
    $Global:OUHash = @{}
    Get-ADUser -Filter * | Foreach-Object {
        $OUName = Translate-DNToOU $_.DistinguishedName
        If($OUHash.ContainsKey($OUName)){
            $OUHash.$OUName++
        }ElseIf(!($OUHash.ContainsKey($OUName))){
            $OUHash.Add($OUName,1)
        }
    }
    return $Global:$OUHash
}