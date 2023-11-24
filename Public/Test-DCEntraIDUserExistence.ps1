function Test-DCEntraIDUserExistence {
    <#
        .SYNOPSIS
            Test if an account exists in Entra ID for specified email addresses.

        .DESCRIPTION
            This CMDlet will connect to public endpoints in Entra ID to find out if an account exists for specified email addresses or not. This script works without any authentication to Entra ID. This is called user enumeration in cyber security.

            The script can't see accounts for federated domains (since they are on-prem accounts) but it will tell you what organisation the federated domain belongs to.

            Do not use this script in an unethical or unlawful way. Use it to find weak spots in you Entra ID configuration.

        .PARAMETER Users
            An array of one or more user email addresses to test.

        .PARAMETER UseTorHttpProxy
            Use a running Tor network HTTP proxy that was started by Start-DCTorHttpProxy.

        .EXAMPLE
            Test-DCEntraIDUserExistence -UseTorHttpProxy -Users "user1@example.com", "user2@example.com", "user3@example.onmicrosoft.com"

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
	#>


    param (
        [parameter(Mandatory = $true)]
        [array]$Users,

        [parameter(Mandatory = $false)]
        [switch]$UseTorHttpProxy
    )

    foreach ($User in $Users) {
        # Create custom object for output.
        $TestObject = New-Object -TypeName psobject

        # Add username.
        $TestObject | Add-Member -MemberType NoteProperty -Name "Username" -Value $User

        # Check if user account exists in Entra ID.
        $IfExistsResult = 1

        if ($UseTorHttpProxy) {
            $IfExistsResult = ((Invoke-WebRequest -Proxy "http://127.0.0.1:9150" -Method "POST" -Uri "https://login.microsoftonline.com/common/GetCredentialType" -Body "{`"Username`":`"$User`"}").Content | ConvertFrom-Json).IfExistsResult
        }
        else {
            $IfExistsResult = ((Invoke-WebRequest -Method "POST" -Uri "https://login.microsoftonline.com/common/GetCredentialType" -Body "{`"Username`":`"$User`"}").Content | ConvertFrom-Json).IfExistsResult
        }

        if ($IfExistsResult -eq 0) {
            # Check domain federation status.
            [xml]$Response = ""

            if ($UseTorHttpProxy) {
                [xml]$Response = (Invoke-WebRequest -Proxy "http://127.0.0.1:9150" -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=$User&xml=1").Content
            }
            else {
                [xml]$Response = (Invoke-WebRequest -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=$User&xml=1").Content
            }

            # Add org information.
            $TestObject | Add-Member -MemberType NoteProperty -Name "Org" -Value $Response.RealmInfo.FederationBrandName

            # If domain is Federated we can't tell if the account exists or not :(
            if ($Response.RealmInfo.IsFederatedNS -eq $true) {
                $TestObject | Add-Member -MemberType NoteProperty -Name "UserExists" -Value "Unknown (federated domain: $((($Response.RealmInfo.AuthURL -split "//")[1] -split "/")[0]))"
            }
            # If the domain is Managed (not federated) we can tell if an account exists in Entra ID :)
            else {
                $TestObject | Add-Member -MemberType NoteProperty -Name "UserExists" -Value "Yes"
            }
        }
        else {
            $TestObject | Add-Member -MemberType NoteProperty -Name "UserExists" -Value "No"
        }

        $TestObject
    }
}