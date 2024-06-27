Function Add-RegistryCredential {
    param(
        [Parameter(Mandatory)]
        [String]$Username,

        [Parameter(Mandatory)]
        [string]$Password,

        [Parameter(Mandatory)]
        [ValidateSet('Interactive','System')]
        [string]$LogonType
    )
    
    
    # Define the registry path and key path
    $CredentialRegistryPath = 'HKLM:\Software\CredentialManager\EncryptedCredentials'
    $KeyPath = "$CredentialRegistryPath\$UserName"
    

    If($LogonType -eq 'System'){
        $CheckName = (hostname).ToString() + '$'
        If($Env:USERNAME -ne $CheckName){
            Write-Host "This script has to be run as a scheduled task with System Privlidges to save a Credential to be used by the system later."
        }Else{
            # Create the registry key path if it doesn't exist
            if (-not (Test-Path $KeyPath)) {
                New-Item -Path $KeyPath -Force | Out-Null
            }
            
            # Create a secure string from the password and encrypt it
            $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
            $EncryptedPassword = ConvertFrom-SecureString $SecurePassword
            
            # Store the username and encrypted password in the registry
            New-ItemProperty -Path $KeyPath -Name "Username" -Value $Username -PropertyType "String" -Force | Out-Null
            New-ItemProperty -Path $KeyPath -Name "Password" -Value $EncryptedPassword -PropertyType "String" -Force | Out-Null
        }
    }ElseIf($LogonType -eq 'Interactive'){
        # Create the registry key path if it doesn't exist
        if (-not (Test-Path $KeyPath)) {
            New-Item -Path $KeyPath -Force | Out-Null
        }
        
        # Create a secure string from the password and encrypt it
        $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        $EncryptedPassword = ConvertFrom-SecureString $SecurePassword
        
        # Store the username and encrypted password in the registry
        New-ItemProperty -Path $KeyPath -Name "Username" -Value $Username -PropertyType "String" -Force | Out-Null
        New-ItemProperty -Path $KeyPath -Name "Password" -Value $EncryptedPassword -PropertyType "String" -Force | Out-Null
    }
}
Function Get-RegistryCredential{
    param(
        [Parameter(Mandatory)]
        [String]$Username
    )
    # Define the registry path and key path
    $CredentialRegistryPath = 'HKLM:\Software\CredentialManager\EncryptedCredentials'
    $KeyPath = "$CredentialRegistryPath\$UserName"
    [pscredential]$credObject = New-Object System.Management.Automation.PSCredential (((Get-ItemProperty $KeyPath).Username), ((Get-ItemProperty $KeyPath).Password | ConvertTo-SecureString))
    return $credObject
}
Export-ModuleMember Add-RegistryCredential
Export-ModuleMember Get-RegistryCredential