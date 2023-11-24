function Connect-DCMsGraphAsUser {
    <#
        .SYNOPSIS
            Connect to Microsoft Graph with the Microsoft Graph PowerShell module as a user (using delegated permissions in Graph).

        .PARAMETER Scopes
            The required API permission scopes (delegated permissions). Example: "Policy.ReadWrite.ConditionalAccess", "Policy.Read.All"

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            Connect-DCMsGraphAsUser -Scopes 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All'

        .EXAMPLE
            Connect-DCMsGraphAsUser -Scopes 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All' -Verbose
    #>


    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [string[]]$Scopes
    )


    # Authenticate to Microsoft Graph:
    Write-Verbose -Message "Connecting to Microsoft Graph..."

    Connect-MgGraph -NoWelcome -Scopes $Scopes -ErrorAction Stop

    Write-Verbose -Message "Connected to tenant '$(((Get-MgContext).Account.Split('@'))[1] )'!"
}