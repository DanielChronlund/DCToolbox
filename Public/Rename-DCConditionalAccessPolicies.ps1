function Rename-DCConditionalAccessPolicies {
    <#
        .SYNOPSIS
            Rename Conditional Access policies that matches a specific prefix.

        .DESCRIPTION
            This command helps you to quickly rename a bunch of Conditional Access policies by searching for a specific prefix.

            If you dontt specify a PrefixFilter, ALL policies will be modified to include the new prefix .

        .PARAMETER PrefixFilter
            Only toggle the policies with this prefix.

        .PARAMETER AddCustomPrefix
            Adds a custom prefix to all policy names.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            Rename-DCConditionalAccessPolicies -PrefixFilter 'PILOT - ' -AddCustomPrefix 'PROD - '

        .EXAMPLE
            Rename-DCConditionalAccessPolicies -PrefixFilter 'GLOBAL - ' -AddCustomPrefix 'REPORT - GLOBAL - '

        .EXAMPLE
            Rename-DCConditionalAccessPolicies -AddCustomPrefix 'OLD - '
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $false)]
        [string]$PrefixFilter = '',

        [parameter(Mandatory = $true)]
        [string]$AddCustomPrefix
    )


    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Check PowerShell version.
    Confirm-DCPowerShellVersion -Verbose


    # Check Microsoft Graph PowerShell module.
    Install-DCMicrosoftGraphPowerShellModule -Verbose


    # Connect to Microsoft Graph.
    Connect-DCMsGraphAsUser -Scopes 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All' -Verbose


    if ($PrefixFilter -eq '') {
        # Prompt for confirmation:
        $title    = 'Confirm'
        $question = "Do you want to add prefix '$AddCustomPrefix' to ALL Conditional Access policies in tenant '$(((Get-MgContext).Account.Split('@'))[1] )'?"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    } else {
        # Prompt for confirmation:
        $title    = 'Confirm'
        $question = "Do you want to rename all Conditional Access policies with prefix '$PrefixFilter' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )' to '$AddCustomPrefix'?"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    }


    # Modify all existing policies.
    Write-Verbose -Verbose -Message "Looking for Conditional Access policies to rename..."
    $ExistingPolicies = Get-MgIdentityConditionalAccessPolicy


    foreach ($Policy in $ExistingPolicies) {
        if ($Policy.DisplayName.StartsWith($PrefixFilter)) {

            if ($PrefixFilter -eq '') {
                Write-Verbose -Verbose -Message "Adding prefix '$AddCustomPrefix' to policy '$($Policy.DisplayName)'..."

                # Rename policy:
                $params = @{
                    DisplayName = "$AddCustomPrefix$($Policy.DisplayName)"
                }

                Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -BodyParameter $params

                Start-Sleep -Seconds 1
            } else {
                Write-Verbose -Verbose -Message "Renaming '$($Policy.DisplayName)' to '$($Policy.DisplayName -replace $PrefixFilter, $AddCustomPrefix)'..."

                # Rename policy:
                $params = @{
                    DisplayName = "$($Policy.DisplayName -replace $PrefixFilter, $AddCustomPrefix)"
                }

                Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -BodyParameter $params

                Start-Sleep -Seconds 1
            }
        }
    }


    Write-Verbose -Verbose -Message "Done!"
}