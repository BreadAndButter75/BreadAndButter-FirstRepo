function Get-AllProperties {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]$InputObject
    )

    process {
        # Get all properties of the input object
        $Properties = $InputObject | Get-Member -MemberType Property | Select-Object -ExpandProperty Name

        # Select and output only the properties from the input object
        $InputObject | Select-Object -Property $Properties
    }
}
