Function Get-ADGuidMap {
    # Search AD and gather the GUIDs associated with Permissions and Attributes. 
    # These GUIDs are defined the same across All AD Environments.
    $rootdse = Get-ADRootDSE
    $GUIDMap = @{}
    $GUIDMapParams @{
        SearchBase = ($rootdse.SchemaNamingContext)
        LDAPFilter = "(schemaidguid=*)"
        Properties = ("LDAPDisplayNAme","schemaIDGUID")
    }

    Get-ADObject @GuidMapParams | ForEach-Object {$GUIDMap[$_.LDAPDisplayNAme] = [System.GUID]$_.schemaIDGUID}
    return $GUIDMap
}