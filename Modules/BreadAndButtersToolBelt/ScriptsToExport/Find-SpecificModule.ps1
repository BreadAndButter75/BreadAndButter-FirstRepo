function Find-SpecificModule {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ModuleNames,  # Accepts multiple module names with wildcards
        
        [switch]$Remove
    )

    # Get all module paths from $env:PSModulePath
    $modulePaths = $env:PSModulePath -split [System.IO.Path]::PathSeparator
    $results = @()

    foreach ($path in $modulePaths) {
        if (Test-Path $path) {
            # Get all directories in the module path
            $moduleDirs = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue | 
                Where-Object { $ModuleNames | ForEach-Object { $_ -like $_.Name } }

            foreach ($moduleDir in $moduleDirs) {
                # Extract module version (if subfolders exist)
                $subDirs = Get-ChildItem -Path $moduleDir.FullName -Directory -ErrorAction SilentlyContinue
                if ($subDirs) {
                    foreach ($subDir in $subDirs) {
                        # Ensure version directory structure
                        if ($subDir.Name -match '^\d+\.\d+(\.\d+)?$') {
                            $results += [PSCustomObject]@{
                                ModuleName   = $moduleDir.Name
                                Path         = $subDir.FullName
                                Version      = $subDir.Name
                                LastModified = $subDir.LastWriteTime
                            }

                            if ($Remove) {
                                try {
                                    Remove-Item -Path $subDir.FullName -Recurse -Force -ErrorAction Stop
                                    Write-Host "Removed: $($subDir.FullName)" -ForegroundColor Green
                                } catch {
                                    Write-Host "Failed to remove: $($subDir.FullName) - $_" -ForegroundColor Red
                                }
                            }
                        }
                    }
                }
                else {
                    # Module without versioned subdirectories
                    $results += [PSCustomObject]@{
                        ModuleName   = $moduleDir.Name
                        Path         = $moduleDir.FullName
                        Version      = "Unknown"
                        LastModified = $moduleDir.LastWriteTime
                    }

                    if ($Remove) {
                        try {
                            Remove-Item -Path $moduleDir.FullName -Recurse -Force -ErrorAction Stop
                            Write-Host "Removed: $($moduleDir.FullName)" -ForegroundColor Green
                        } catch {
                            Write-Host "Failed to remove: $($moduleDir.FullName) - $_" -ForegroundColor Red
                        }
                    }
                }
            }
        }
    }

    if ($results) {
        return $results
    } else {
        Write-Host "No matching modules found." -ForegroundColor Yellow
        return $null
    }
}

# Example Usage:
# Find-ModuleInPath -ModuleNames "Az.*"
# Find-ModuleInPath -ModuleNames "Az.*", "PSScriptAnalyzer"
# Find-ModuleInPath -ModuleNames "Az.Accounts", "Az.Storage" -Remove
