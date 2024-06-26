Function Get-ADGuidMap {
    # Search AD and gather the GUIDs associated with Permissions and Attributes. 
    # These GUIDs are defined the same across All AD Environments.
    $rootdse = Get-ADRootDSE
    $GUIDMap = @{}
    $GUIDMapParams = @{
        SearchBase = ($rootdse.SchemaNamingContext)
        LDAPFilter = "(schemaidguid=*)"
        Properties = ("LDAPDisplayNAme","schemaIDGUID")
    }

    Get-ADObject @GuidMapParams | ForEach-Object {$GUIDMap[$_.LDAPDisplayNAme] = [System.GUID]$_.schemaIDGUID}
    return $GUIDMap
}
Function Get-ADExtendedRightsMap {
    # Search AD and gather GUIDs associated with extended rights
    $rootdse = Get-ADRootDSE
    $ExtendedRightsMapParam = @{
        SearchBase = ($rootdse.ConfigurationNamingContext)
        LDAPFilter = "(&(objectclass=controlAccessRight)(rightsguid=*))"
        Properties = ("displayName","rightsGuid")
    }
    $ExtendedRightsMap = @{}
    Get-ADObject @ExtendedRightsMapParam | Foreach-Object {$ExtendedRightsMap[$_.displayName] = [System.GUID]$_.rightsGuid }
    return $ExtendedRightsMap
}
Function Translate-DNtoDomainName {
    param (
        [Parameter(Mandatory)]
        [string]
        $DistinguishedName
    )
    $Domain = (($DistinguishedName -split ",") -match "DC=") -replace "DC=" -join "."
    Return $Domain
} 
function Add-DelegatedPermissionsToOU {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ParameterSetName = 'Default')]
        [Parameter(Mandatory, ParameterSetName = 'CustomPermission')]
        [string]$OUDistinguishedName,

        [Parameter(Mandatory, ParameterSetName = 'Default')]
        [Parameter(Mandatory, ParameterSetName = 'CustomPermission')]
        [string]$Identity,

        [Parameter(Mandatory, ParameterSetName = 'Default')]
        [ValidateSet("DisableUsers","ResetPasswords")]
        [string[]]$Permission
    )
    begin {
        try {
            If(!($GuidMap)){
                $Global:GUIDMap = Get-ADGuidMap
            }
            If(!($ERM)){
                $Global:ERM = Get-ADExtendedRightsMap
            }
            
            # Define the Domain
            $OUDomain = Translate-DNtoDomainName $OUDistinguishedName
            # Define and Verify OUs for ACL Adjustment
            $DN = Get-ADOrganizationalUnit -Identity $OUDistinguishedName -Server $OUDomain | Select-Object -ExpandProperty DistinguishedName 

            # Get the ACL of the OU that we want to operate on.
            $ACL = Get-ACL "AD:\$DN" 

            # Get the SID of the Identity we're operating on.
            $IdentityName = $Identity.Split('\')[1]
            $IdentityDomain = $Identity.Split('\')[0]
            $SID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADUser $IdentityName -server $IdentityDomain).SID 
        }
        catch {
            Write-Host "An Error occured in defining stage of the script." -ForegroundColor Red
            Write-Host $Error[0]
        }
    }
    process {
        switch ($PSCmdlet.ParameterSetName) {
            'Default' {
                switch ($Permission) {
                    DisableUsers { 
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID,"ReadProperty","Allow",$Global:GUIDMap['UserAccountControl'],"Descendents",$Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID,"WriteProperty","Allow",$Global:GUIDMap['UserAccountControl'],"Descendents",$Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                     }
                    ResetPasswords { 
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID,"ExtendedRight","Allow",$Global:ERM["Reset Password"],"Descendents",$Global:GUIDMap['User'] 
                        $ACL.AddAccessRule($ace)
                     }
                }
            }
            'CustomPermissions' {
                
            }
        }
    }    
    end {
        # After Adding the permissions to the ACL. 
        Set-Acl -Path "AD:\$DN" -AclObject $ACL 
    }
} 