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
    # Simple function to translate a DistinguishedName formatted like "OU=Test,OU=Admin,OU=Privleged Groups,DC=Contoso,DC=Com" to the domain fqdn of "Contoso.Com"
    param (
        [Parameter(Mandatory)]
        [string]
        $DistinguishedName
    )
    $Domain = (($DistinguishedName -split ",") -match "DC=") -replace "DC=" -join "."
    Return $Domain
} 
function Add-DelegatedPermissionsToOU {
    # The true purpose of this function is to assist/replace the GUI Delegation Wizard within Active Direcory Users and Computers. 
    # The nice part about this function is nothing is off limits. So you can target much more than the gui. Containers, any OU that you want, etc. 
    # As well you can add any permission you want. It requires a basic understanding of ActiveDirectoryAccessRules more information can be found in the microsoft doc titled "ActiveDirectoryAccessRuleClass"
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
        [string[]]$Permission,

        [Parameter(Mandatory, ParameterSetName = 'CustomPermission')]
        [ValidateSet("AccessSystemSecurity", "CreateChild", "Delete", "DeleteChild", "DeleteTree", "ExtendedRight", "GenericAll", "GenericExecute", "GenericRead", "GenericWrite", "ListChildren", "ListObject", "ReadControl", "ReadProperty", "Self", "Synchronize", "WriteDacl", "WriteOwner", "WriteProperty")]
        [string]$ActiveDirectoryRight,

        [Parameter(Mandatory, ParameterSetName = 'CustomPermission')]
        [ValidateSet("Allow","Deny")]
        [string]$AccessControlType,

        # The GUIDReference Parameter is referring to the Name of the Property in either the GUIDMap or the ExtendedRightsMap The script will error if an ExtendedRightsMap GUID or GUIDReference is supplied without the "ExtendedRight" $ActiveDirectoryRight being supplied. If the GUID is known, the GUID can be supplied as well.
        [Parameter(Mandatory,ParameterSetName = 'CustomPermission')]
        [string]$GUIDReference,

        [Parameter(Mandatory,ParameterSetName = 'CustomPermission')]
        [ValidateSet("All","Children","Descendents","None","SelfAndChildren")]
        [string]$Inheritance,

        [Parameter(Mandatory,ParameterSetName = 'CustomPermission')]
        [string]$InheritanceObjectType
        #
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
                    # This section here is where you can add additional permissions. They are to be defined as follows:
                    <#
                    PermissionName {
                        # This will need to be repeated for every specific permission granted. For example the Disable Users has read and write being granted. I believe this is redundant. If there is no need to read the property Write rights would be enough.
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule <IdentityReference>,<ActiveDirectoryRights>,<AccessControlType>,<GUID>,<Inheritance>,<InheritedObjectType>
                        $ACL.AddAccessRule($ace)

                        # Each argument of the ActiveDirectoryAccessRule used in the $ACE is important and has a couple of options.
                        # <IdentityReference> - We're using $SID here to represent the SID of the Object that is the trustee of the Access Rule.
                        # <ActiveDirectoryRights> - This is a generic Right. There are plenty of predefined definitions. ReadProperty,CreateChild,DeleteTree,etc. And important one is ExtendedRight this signify's that you'll be refrencing the Extended rights Map to and pulling a permission from that. This also involves constructing the statement differently. More information can be found in the Microsoft Doc "ActiveDirectoryRights Enum"
                        # <AccessControlType> - This is a boolean field. The options are either Allow or Deny. 
                        # <GUID> - This can be a number of things. It's usually a property if using a standard ActiveDirectoryRight otherwise it could reference the Right that you're looking for in the ExtendedRightsMap
                        # <Inheritance> - This is is the property that determines how the permission will be propagated from the object you're placing it on. On an OU or Container, options here could be All, Children, Descendents, None, SelfAndChildren. They can be defined as follows. (All - The object you're tageting, children, and decendents recursive below the target), (Children - This targets only the immediate children below the SID you're targeting.), (Descendents - This targets the immediate Children and the Recurisve Descendents below the Target SID.), (None - This indicates that Inheritance is disabled and the permission should be granted specifically on the object you're targeting and only that object. For example when targeting a single User or Group. be warned if attempting that the structure of the $ace is different.), (SelfAndChildren - This is the object, and it's immediate children only. No descendents.)
                        # <InheritedObjectType> - This is a Guid of an object Type. For example User, Computer, OrganizationalUnit, or even all. You need to identify the GUID though, that can be found in the $GuidMap. 
                        #


                        
                    }
                    
                    #>
                    DisableUsers { 
                        # Grant Read Permission to the UserAccountControl Property on all descendent User Objects
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID,"ReadProperty","Allow",$Global:GUIDMap['UserAccountControl'],"Descendents",$Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                        # Grant Write Permission to the UserAccountControl Property on all descendent User Objects
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID,"WriteProperty","Allow",$Global:GUIDMap['UserAccountControl'],"Descendents",$Global:GUIDMap['User']
                        $ACL.AddAccessRule($ace)
                     }
                    ResetPasswords { 
                        # Grant the Extended Right 'ResetPassword' on all descendent User objects
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID,"ExtendedRight","Allow",$Global:ERM["Reset Password"],"Descendents",$Global:GUIDMap['User'] 
                        $ACL.AddAccessRule($ace)
                     }
                }
            }
            # This is a section of script will allow you to provide your own arguments to build an $ace to add to AD
            # Both the Identity and The Target will be populated in common with the Default ParameterSet. Everything else will need to be specified via the parameters of the Function.
            #  
            'CustomPermissions' {
                
            }
        }
    }    
    end {
        # After Adding the permissions to the ACL. 
        Set-Acl -Path "AD:\$DN" -AclObject $ACL 
    }
} 