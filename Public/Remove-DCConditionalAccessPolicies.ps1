

function Remove-DCConditionalAccessPolicies {
    <#
        .SYNOPSIS
            Delete ALL Conditional Access policies in a tenant.

        .DESCRIPTION
            This script is a proof of concept and for testing purposes only. Do not use this script in an unethical or unlawful way. Don’t be stupid!

            This CMDlet uses Microsoft Graph to automatically delete all Conditional Access policies in a tenant. It was primarily created to clean-up lab tenants, and as an attack PoC.

            This CMDlet will prompt you for confirmation multiple times before deleting policies.

        .PARAMETER PrefixFilter
            Only delete the policies with this prefix.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            Remove-DCConditionalAccessPolicies

        .EXAMPLE
            Remove-DCConditionalAccessPolicies -PrefixFilter 'TEST - '
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $false)]
        [string]$PrefixFilter = ''
    )


    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Check PowerShell version.
    Confirm-DCPowerShellVersion -Verbose


    # Check Microsoft Graph PowerShell module.
    Install-DCMicrosoftGraphPowerShellModule -Verbose


    # Connect to Microsoft Graph.
    Connect-DCMsGraphAsUser -Scopes 'Policy.Read.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All' -Verbose


    # Prompt for confirmation:
    if ($PrefixFilter -ne '') {
        $title    = 'Confirm'
        $question = "Do you want to remove all Conditional Access policies with prefix '$PrefixFilter' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )'? WARNING: ALL THESE POLICIES WILL BE DELETED!!"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    } else {
        $title    = 'Confirm'
        $question = "Do you want to remove all Conditional Access policies in tenant '$(((Get-MgContext).Account.Split('@'))[1] )'? WARNING: ALL POLICIES WILL BE DELETED!!"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    }


    # Prompt for confirmation:
    $title    = 'Confirm'
    $question = "ARE YOU REALLY REALLY SURE?"
    $choices  = '&Yes', '&No'

    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host ""
        Write-Verbose -Verbose -Message "Starting deletion..."
    } else {
        return
    }


    # Delete all existing policies.
    $ExistingPolicies = Get-MgIdentityConditionalAccessPolicy


    foreach ($Policy in $ExistingPolicies) {
        if ($Policy.DisplayName.StartsWith($PrefixFilter)) {
            Start-Sleep -Seconds 1
            Write-Verbose -Verbose -Message "Deleting '$($Policy.DisplayName)'..."
            $GraphUri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($Policy.Id)"

            Invoke-MgGraphRequest -Method 'DELETE' -Uri $GraphUri -ErrorAction SilentlyContinue | Out-Null
        }
    }


    Write-Verbose -Verbose -Message "Done!"
}
