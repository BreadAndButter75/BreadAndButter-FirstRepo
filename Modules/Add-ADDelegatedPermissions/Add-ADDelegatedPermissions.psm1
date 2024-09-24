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
        [ValidateSet("DisableUsers","ResetPasswords","JoinComputers")]
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
                    UnlockUserAccounts {
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ExtendedRight", "Allow", $Global:ERM['User-Force-Change-Password'], "Descendents", $Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ExtendedRight", "Allow", $Global:ERM['User-Account-Control-Change'], "Descendents", $Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                    }
                    ManageOUs {
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "CreateChild, DeleteChild", "Allow", $Global:GUIDMap['OrganizationalUnit'], "Descendents", $Global:GUIDMap['OrganizationalUnit']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "WriteProperty", "Allow", "00000000-0000-0000-0000-000000000000", "Descendents", $Global:GUIDMap['OrganizationalUnit']
                        $ACL.AddAccessRule($ace)
                    }
                    ManageGroupMembership {
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "WriteProperty", "Allow", $Global:GUIDMap['member'], "Descendents", $Global:GUIDMap['Group']
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty", "Allow", $Global:GUIDMap['member'], "Descendents", $Global:GUIDMap['Group']
                        $ACL.AddAccessRule($ace)
                        $ACL.AddAccessRule($ace)
                    }
                    ManageSPNs {
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "WriteProperty", "Allow", $Global:GUIDMap['servicePrincipalName'], "Descendents", $Global:GUIDMap['Computer']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "WriteProperty", "Allow", $Global:GUIDMap['servicePrincipalName'], "Descendents", $Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                    }
                    ManageHomeDirectories {
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty, WriteProperty", "Allow", $Global:GUIDMap['homeDirectory'], "Descendents", $Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty, WriteProperty", "Allow", $Global:GUIDMap['profilePath'], "Descendents", $Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                    }
                    MoveComputerFromOU {
                        # Source OU permissions
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "DeleteChild", "Allow", $Global:GUIDMap['Computer'], "Descendents", "00000000-0000-0000-0000-000000000000"
                        $ACL.AddAccessRule($ace)
                    }
                    MoveComputerToOU {
                        # Destination OU permissions
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "CreateChild", "Allow", $Global:GUIDMap['Computer'], "Descendents", "00000000-0000-0000-0000-000000000000"
                        $ACL.AddAccessRule($ace)
                    }
                    MoveUserFromOU{
                        # Source OU permissions
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "DeleteChild", "Allow", $Global:GUIDMap['User'], "Descendents", "00000000-0000-0000-0000-000000000000"
                        $ACL.AddAccessRule($ace)
                    }
                    MoveUserToOU {
                        # Destination OU permissions
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "CreateChild", "Allow", $Global:GUIDMap['User'], "Descendents", "00000000-0000-0000-0000-000000000000"
                        $ACL.AddAccessRule($ace)
                    }
                    ManageDNSRecords {
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty, WriteProperty", "Allow", $Global:GUIDMap['dnsRecord'], "Descendents", $Global:GUIDMap['dnsNode']
                        $ACL.AddAccessRule($ace)
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "DeleteChild", "Allow", $Global:GUIDMap['dnsRecord'], "Descendents", $Global:GUIDMap['dnsNode']
                        $ACL.AddAccessRule($ace)
                    }
                    WriteMail {
                        # Write the "mail" attribute
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty, WriteProperty", "Allow", $Global:GUIDMap['mail'], "Descendents", $Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)

                        # Write the "proxyAddresses" attribute
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "ReadProperty, WriteProperty", "Allow", $Global:GUIDMap['proxyAddresses'], "Descendents", $Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                    }
                    WriteMSExchAttributes {
                        # Write the "msExchHomeServerName" attribute
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "WriteProperty", "Allow", $Global:GUIDMap['msExchHomeServerName'], "Descendents", $Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)

                        # Write the "msExchUserAccountControl" attribute
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "WriteProperty", "Allow", $Global:GUIDMap['msExchUserAccountControl'], "Descendents", $Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                    }
                    ManageMSExchMailboxSecurityDescriptor {
                       # Write the "msExchMailboxSecurityDescriptor" attribute
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "WriteProperty", "Allow", $Global:GUIDMap['msExchMailboxSecurityDescriptor'], "Descendents", $Global:GUIDMap['User']
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
