function New-Log {
    param (
        [Parameter(Mandatory)]
        [String]
        $LogName
    )
    process {
        $LogPath = "C:\temp\Logs"
        If(!(Test-Path $LogPath)){
            mkdir $LogPath
        }
        If(!(Test-Path $LogPath\$LogName)){
            New-Item -Path $LogPath -Name $LogName -ItemType File
        }
    }
}
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Message,
        [Parameter(Mandatory=$True)]
        [string]$LogName
    )

    Process {
        $LogPath = "C:\temp\Logs"
        If(!(Test-Path $LogPath\$LogName)){
            New-Log $LogName
        }
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "$timestamp - $Message"
        Add-Content -Value $logEntry -Path (Get-ChildItem -Path $LogPath | Where-Object -Property Name -EQ $LogName).FullName
    }
}
function Clear-Log {
    param (
        # Parameter help description
        [Parameter(Mandatory)]
        [String]
        $LogFile
    )
    Process {
        # Set the cutoff date
        $CutoffDate = (Get-Date).AddDays(-90)

        # Get The Full Path
        $TranscriptPath = 'C:\temp\Logs\' + $LogFile
        

        try {
            # Read the transcript file
            #$Transcript = Get-Content $TranscriptPath -ErrorAction SilentlyContinue
            If(Get-Content $TranscriptPath -ErrorAction SilentlyContinue){
                $Transcript = Get-Content $TranscriptPath
                # Initialize an array to hold the new transcript
                $NewTranscript = @()

                # Iterate over the lines in the transcript
                foreach ($Line in $Transcript) {
                    # Check if the line contains a timestamp
                    if ($Line -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}') {
                        #Write-Host $Line -ForegroundColor Yellow
                        # Parse the timestamp
                        $Timestamp = [DateTime]::ParseExact($Matches.Values, "yyyy-MM-dd HH:mm:ss", $null)

                        # Check if the timestamp is older than the cutoff date
                        if ($Timestamp -lt $CutoffDate) {
                            # Skip this line
                            #continue
                        }ElseIf ($Timestamp -ge $CutoffDate) {
                            # Add the line to the new transcript
                            $NewTranscript += $Line   
                        }
                    }

                    
                }

                Remove-Item $TranscriptPath -Force
                # Write the new transcript to the file
                $NewTranscript | Set-Content $TranscriptPath -Force
            }
        }
        catch {
            <#Do this if a terminating exception happens#>
        }
    }    
}
Export-ModuleMember New-Log 
Export-ModuleMember Write-Log
Export-ModuleMember Clear-Log
