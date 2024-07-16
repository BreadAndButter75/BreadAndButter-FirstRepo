Function Enable-MailOnADGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=0)]
        [string[]]$Group,
        
        [string]$Server,
        
        [string]$upnsuffix
    )
    begin{
        if($Server){
            $Domain = Get-ADDomain -Server $Server
        }Else{
            $Domain = Get-ADDomain -Current LocalComputer
        }
        if($upnsuffix){
            if($upnsuffix -like "@*"){
                
            }ElseIf($upnsuffix -like "*.*"){
                $upnsuffix = "@" + $upnsuffix
            }Else{
                Write-Host "Error: " -ForegroundColor Red -NoNewline; Write-Host ' $UPNsuffix' -ForegroundColor DarkYellow -NoNewline; Write-Host " is not properly defined as a domain in the format " -NoNewline; Write-Host  "Contoso.Com" -ForegroundColor Green -NoNewline; Write-Host " or " -NoNewline; Write-Host "@Contoso.Com" -ForegroundColor Green
            }
        }Else{
            $upnsuffix = "@" + $Domain.DNSRoot
        }
    }
    Process{
        Foreach($grp in $Group){  
        $Mail = $grp.Replace(' ','') + $upnsuffix 
        $Object = Get-ADGroup -Filter "Name -like '$grp'" -Properties * -Server $Domain.DNSRoot
            If($Object.Mail -eq $null){
                $Object | Set-ADGroup -Server $Domain.DNSRoot -Replace @{mail="$Mail"} -Verbose
            }ElseIf($Object.Mail -ne $Mail){
                Write-Host "Warning: " -ForegroundColor Yellow -NoNewline; Write-Host "The mail property is already set on the supplied group $Group. It's currently set to $($Object.Mail). " -NoNewline;
                $Continue = $null
                While(($Continue -ne 'Y') -And ($Continue -ne 'N')){
                    $Continue = Read-Host "Would you like to overwrite the Mail Property? Y or N"
                }
                If($Continue -eq 'Y'){
                    $Object | Set-ADGroup -Server $Domain.DNSRoot -Replace @{mail="$Mail"} -Verbose
                }ElseIf($Continue -eq 'N'){

                }
            }
        }
    }
    End {
    }

}
Export-ModuleMember Enable-MailOnADGroup
