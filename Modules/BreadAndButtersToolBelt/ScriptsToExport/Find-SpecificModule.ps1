function Find-SpecificModule {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [switch]$Remove
    )

    # Get all module paths from $env:PSModulePath
    $modulePaths = $env:PSModulePath -split [System.IO.Path]::PathSeparator

    $foundModules = @()

    foreach ($path in $modulePaths) {
        if (Test-Path $path) {
            $moduleDirs = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq $ModuleName }

            foreach ($moduleDir in $moduleDirs) {
                $fullPath = $moduleDir.FullName
                $foundModules += $fullPath

                if ($Remove) {
                    try {
                        Remove-Item -Path $fullPath -Recurse -Force -ErrorAction Stop
                        Write-Host "Removed: $fullPath" -ForegroundColor Green
                    } catch {
                        Write-Host "Failed to remove: $fullPath - $_" -ForegroundColor Red
                    }
                }
            }
        }
    }

    if ($foundModules) {
        return $foundModules
    } else {
        Write-Host "Module '$ModuleName' not found in any paths." -ForegroundColor Yellow
        return $null
    }
}

