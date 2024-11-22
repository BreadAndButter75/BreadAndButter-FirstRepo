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
        [ValidateSet("DisableUsers","ResetPasswords","JoinComputers","WritePOSIXAttributes","ReadComputerAttributesForSecurityDashboard")]
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
                    JoinComputers { 
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "Self", "Allow", $Global:GUIDMap['dNSHostName'],"Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ExtendedRight", "Allow", $Global:ERM['Allowed to Authenticate'], "Descendents", $Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ExtendedRight", "Allow", $Global:ERM['Reset Password'], "Descendents", $Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ExtendedRight", "Allow", $Global:ERM['Change Password'], "Descendents", $Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty","Allow","00000000-0000-0000-0000-000000000000","Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "CreateChild, DeleteChild", "Allow", $Global:GUIDMap['Computer'], "Descendents","00000000-0000-0000-0000-000000000000"
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty, WriteProperty", "Allow", $Global:GUIDMap['UserAccountControl'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "Self", "Allow", $Global:GUIDMap['servicePrincipalName'],"Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace) 
                    }
                    WritePOSIXAttributes{
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty, WriteProperty", "Allow", $Global:GUIDMap['uidNumber'], "Descendents",$Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty, WriteProperty", "Allow", $Global:GUIDMap['gidNumber'], "Descendents",$Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty, WriteProperty", "Allow", $Global:GUIDMap['unixHomeDirectory'], "Descendents",$Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty, WriteProperty", "Allow", $Global:GUIDMap['loginShell'], "Descendents",$Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty, WriteProperty", "Allow", $Global:GUIDMap['gecos'], "Descendents",$Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                    }
                    ReadComputerAttributesForSecurityDashboard{
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['cn'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['Description'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['DistinguishedName'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['DNSHostName'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['domain'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['extensionAttribute8'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['LastLogonTimestamp'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['memberOf'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['objectSid'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['OperatingSystem'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['OperatingSystemServicePack'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['OperatingSystemVersion'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['pwdLastSet'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['ServicePrincipalName'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['UserAccountControl'], "Descendents",$Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['whenCreated'], "Descendents",$Global:GUIDMap['Computer']
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
 
 
