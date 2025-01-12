# Get the full path to the current module directory
$ModuleBasePath = $PSScriptRoot
$ScriptsPath = Join-Path -Path $ModuleBasePath -ChildPath "ScriptsToExport"

# Import all .ps1 scripts in the ScriptsToExport folder
Get-ChildItem -Path $ScriptsPath -Filter '*.ps1' | ForEach-Object {
    # Dot source each script to load its functions into the current session
    . $_.FullName
}

# Export all functions defined in the loaded scripts
$FunctionsToExport = (Get-Command -CommandType Function | Where-Object { $_.Source -like "$ScriptsPath\*" }).Name
Export-ModuleMember -Function $FunctionsToExport
