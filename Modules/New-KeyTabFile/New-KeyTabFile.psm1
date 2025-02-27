function New-KeytabFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string[]]$SPN,
        [Parameter(Mandatory=$true)]
        [string]$OutFile,
        [switch]$ResetPassword
    )
    # This function generates a Kerberos keytab file for the given service principal name(s) (SPNs).
    # It updates the corresponding AD user account(s) by:
    #   - Adding the SPN to the account's servicePrincipalName attribute (using Set-ADObject instead of setspn).
    #   - Enabling Kerberos AES 256-bit encryption support on the account.
    # If -ResetPassword is specified, the account's password is reset to a random value for keytab generation.
    # The ktpass tool is then used to create the .keytab file with default options (KRB5_NT_PRINCIPAL, AES256-SHA1).
    #
    # Parameters:
    #   -SPN            One or more strings in the format of a setspn command 
    #                   (e.g. "setspn -s hdb/server01.contoso.com CONTOSO\\ServiceAccount01").
    #   -OutFile        Path to the output .keytab file to create.
    #   -ResetPassword  Switch to reset the account password (generate new password) before creating the keytab.
    #
    # Usage example:
    #   New-KeytabFile -SPN "setspn -s hdb/server01.contoso.com CONTOSO\\ServiceAccount01" `
    #                 -OutFile "C:\\Keytabs\\Service01.keytab" -ResetPassword -Verbose
    #
    # Note: Requires the ActiveDirectory module and appropriate permissions (e.g., Domain Admin or Account Operators).
    
    Begin {
        # Import ActiveDirectory module for AD cmdlets (if not already loaded).
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        catch {
            Throw "ActiveDirectory module is not available. Install RSAT or run on a domain controller."
        }
    }
    Process {
        # If the output file already exists, remove it to avoid merging old data inadvertently.
        if (Test-Path $OutFile) {
            Remove-Item $OutFile -Force
            Write-Verbose "Removed existing keytab file '$OutFile' to create a new one."
        }
        
        $firstEntry = $true  # Flag to track the first SPN (for ktpass /out vs /in).
        foreach ($spnCommand in $SPN) {
            try {
                # Parse the SPN command string to extract SPN and account.
                # Expected format: "setspn -s <SPN_value> <DOMAIN\\AccountName>"
                if ($spnCommand -match '(?i)setspn\s+-s\s+(?<ServiceSPN>\S+)\s+(?<ADAccount>\S+)$') {
                    $spnValue = $Matches['ServiceSPN']
                    $accountId = $Matches['ADAccount']
                }
                else {
                    Write-Error "Invalid SPN command format: '$spnCommand'. Skipping this entry."
                    continue
                }
                Write-Verbose "Parsed SPN: '$spnValue'; Account: '$accountId'."
                
                # Get the AD user object for the account (to update SPN and encryption settings).
                $adUser = Get-ADUser -Identity $accountId -Properties ServicePrincipalName, msDS-SupportedEncryptionTypes -ErrorAction Stop
                Write-Verbose "Retrieved AD user for $accountId (DN: $($adUser.DistinguishedName))."
                
                # Enable AES256 Kerberos encryption support on the account (sets msDS-SupportedEncryptionTypes).
                Set-ADUser -Identity $adUser -KerberosEncryptionType AES256 -ErrorAction Stop
                Write-Verbose "Enabled AES 256-bit Kerberos encryption on account $accountId (msDS-SupportedEncryptionTypes updated)&#8203;:contentReference[oaicite:0]{index=0}."
                
                # Add the SPN to the user's servicePrincipalName attribute if it's not already present.
                if ($adUser.ServicePrincipalName -notcontains $spnValue) {
                    Set-ADObject -Identity $adUser.ObjectGuid -Add @{servicePrincipalName = $spnValue} -ErrorAction Stop
                    Write-Verbose "Added SPN '$spnValue' to the servicePrincipalName of $accountId."
                }
                else {
                    Write-Verbose "SPN '$spnValue' already exists on $accountId; skipping addition."
                }
                
                # Construct the Kerberos principal (SPN@REALM) for ktpass.
                # e.g., if SPN is hdb/server01.contoso.com and domain is contoso.com, principal = hdb/server01.contoso.com@CONTOSO.COM
                $domainName = ($adUser.UserPrincipalName -split '@')[-1]
                if (-not $domainName) {
                    $domainName = (Get-ADDomain).DNSRoot  # Fallback to current domain's DNS name.
                }
                $realm = $domainName.ToUpper()
                $principal = "$spnValue@$realm"
                Write-Verbose "Kerberos principal for keytab: $principal"
                
                # Handle account password for ktpass.
                # If resetting, generate a random password and set it on the account. Otherwise, prompt for current password.
                $passwordParam = ""
                if ($ResetPassword.IsPresent) {
                    # Generate a random 16-character password (with at least 3 non-alphanumeric chars).
                    $newPlainPassword = [System.Web.Security.Membership]::GeneratePassword(16, 3)
                    $secureNewPassword = ConvertTo-SecureString $newPlainPassword -AsPlainText -Force
                    # Reset the AD account password to this new value.
                    Set-ADAccountPassword -Identity $adUser -NewPassword $secureNewPassword -Reset -ErrorAction Stop
                    Write-Verbose "Reset password for $accountId to a new random value for keytab generation."
                    # Prepare ktpass password parameter with the new password.
                    $passwordParam = "-pass `"$newPlainPassword`""
                }
                else {
                    # Prompt for the account's current password (since we're not resetting it).
                    $secureCurrentPassword = Read-Host -AsSecureString -Prompt "Enter current password for account $accountId"
                    if (-not $secureCurrentPassword) {
                        Write-Error "No password provided for $accountId. Cannot generate keytab without the account password."
                        continue
                    }
                    # Convert secure string to plain text for ktpass (in-memory only).
                    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureCurrentPassword))
                    $passwordParam = "-pass `"$plainPassword`""
                    Write-Verbose "Using provided password for $accountId to generate keytab."
                }
                
                # Build the ktpass command arguments.
                # Using defaults: -ptype KRB5_NT_PRINCIPAL (recommended principal type)&#8203;:contentReference[oaicite:1]{index=1} 
                # and -crypto AES256-SHA1 (uses 256-bit AES encryption)&#8203;:contentReference[oaicite:2]{index=2}.
                $ktpassArgs = "/out `"$OutFile`" /princ `"$principal`" /mapuser `"$accountId`" /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL $passwordParam"
                # If appending additional SPNs to the same keytab, include /in to merge with existing file&#8203;:contentReference[oaicite:3]{index=3}.
                if (-not $firstEntry) {
                    $ktpassArgs = "/in `"$OutFile`" $ktpassArgs"
                }
                Write-Verbose "Executing: ktpass $ktpassArgs"
                
                # Run the ktpass command-line tool with the assembled arguments.
                $ktpassOutput = & ktpass $ktpassArgs 2>&1
                if ($LASTEXITCODE -ne 0) {
                    throw "ktpass failed for SPN '$spnValue'. Output: $ktpassOutput"
                }
                else {
                    Write-Verbose "ktpass output: $ktpassOutput"
                }
                
                $firstEntry = $false  # Mark that the first entry has been processed.
            }
            catch {
                Write-Error "Error processing SPN '$spnCommand': $_"
                continue  # Continue to the next SPN if an error occurred on this one.
            }
        }
    }
    End {
        if (Test-Path $OutFile) {
            Write-Verbose "All operations completed. Keytab file created at: $OutFile"
        }
        else {
            Write-Verbose "Keytab file was not created due to errors (see above logs)."
        }
    }
}
