Function Get-ADExtendedRightsMap {
    # Search AD and gather GUIDs associated with extended rights
    $rootdse = Get-ADRootDSE
    $ExtendedRightsMapParam = @{
        SearchBase = ($rootdse.ConfigurationNamingContext)
        LDAPFilter = "(&(objectclass=controlAccessRight)(rightsguid=*))"
        Properties = ("displayName","rightsGuid")
    }
    $ExtendeDRightsMap = @{}
    Get-ADObject @ExtendedRightsMapParam | Foreach-Object {$ExtendedRightsMap[$_.displayName] = [System.GUID]$_.rightsGuid }
}