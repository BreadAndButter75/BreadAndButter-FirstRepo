 # This is a bit of code I wrote up to address some domain hardening changes
 # Set-ADComputerCreator does not work because mS-DS-CreatorSID is a system owned property.
 # Get-ADComputerCreator can help you identify the Creator of one or many computer objects.
 # If the same owner attempts to join the domain the domain join is successful. 
 
 function Get-ADComputerCreator {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,Position=0)][string[]]$ComputerName,
        [Parameter()][string]$Server,
        [Parameter()][pscredential]$Credential
    )
    
    begin {
        $Output = @()
        If(!($Server)){
            $Server = (Get-ADDomain -Current LocalComputer | Select-Object -ExpandProperty DNSRoot)
        }
        $DomainSID = (Get-ADDomain $Server | Select-Object -ExpandProperty DomainSID)

    }
    
    process {
        Foreach($Computer in $ComputerName){
            If($Credential){
                $compinfo = Get-ADComputer $Computer -Server $Server -Credential $Credential -Properties mS-DS-CreatorSID
            }Else{
                $compinfo = Get-ADComputer $Computer -Server $Server -Properties mS-DS-CreatorSID
            }
            If($null -eq $compinfo.'mS-DS-CreatorSID'){
                $item = [PSCustomObject] @{
                        Computer = $($Compinfo.Name)
                        UserID = 'mS-DS-CreatorSID is Null'
                        DisplayName = 'mS-DS-CreatorSID is Null'
                        PasswordLastSet = 'mS-DS-CreatorSID is Null'
                        CreatorSID = $($compinfo.'mS-DS-CreatorSID'.Value)
                    }
            }ElseIf($DomainSID -eq $Compinfo.'mS-DS-CreatorSID'.AccountDomainSid.Value){
                # Joining User is in the same domain as the computer :)
                $Filter = $compinfo.'mS-DS-CreatorSID'
                $Filter = "SID -eq '$Filter'"
                $UserData = Get-ADUser -Filter $Filter -Server $Server -Properties *
                If($null -ne $UserData){
                    $item = [PSCustomObject] @{
                        Computer = $($Compinfo.Name)
                        UserID = $($UserData.SamAccountName)
                        DisplayName = $($UserData.DisplayName)
                        PasswordLastSet = $($UserData.PasswordLastSet)
                        CreatorSID = $($UserData.SID)
                    }
                }Else{
                    $item = [PSCustomObject] @{
                        Computer = $($Compinfo.Name)
                        UserID = 'User could not be found.'
                        DisplayName = 'This implies the user '
                        PasswordLastSet = 'no longer exists. '
                        CreatorSID = $($compinfo.'mS-DS-CreatorSID'.Value)
                    }
                }
            }Else{
                # Joining user is in a different domain as the computer

            }
            

            $Output += $item
            $filter=$null;$UserData=$null;$CompInfo=$null;$item=$null;
        }
    }
    
    end {
        Return $Output
    }
}

function Set-ADComputerCreator {
    param (
        [Parameter(Mandatory)][string[]]$ComputerName,
        [Parameter(Mandatory)][string]$UserID,
        [Parameter()][string]$Server,
        [Parameter()][pscredential]$Credential
    )
    
    begin {
        If(!($Server)){
            $Server = (Get-ADDomain -Current LocalComputer | Select-Object -ExpandProperty DNSRoot)
        }
        $UserSID = (Get-ADUser $UserID -Server $Server | Select-Object -ExpandProperty SID)
        #$PropertyHash = @{'mS-DS-CreatorSID' = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList ($UserSID)}
        #$PropertyHash = @{'mS-DS-CreatorSID' = $UserSID}
        $PropertyHash = @{'mS-DS-CreatorSID' = [System.Security.Principal.SecurityIdentifier]::new($UserSID)}
    }

    Process {
        Foreach($Computer in $ComputerName){
            Get-ADComputer "$ComputerName" -Server $Server | Set-ADComputer -Add $propertyHash -Server $Server
        }
    }

    end {

    }
} 
