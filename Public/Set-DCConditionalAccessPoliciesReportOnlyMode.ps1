function Set-DCConditionalAccessPoliciesReportOnlyMode {
    <#
        .SYNOPSIS
            Toggles Conditional Access policies between 'Report-only' and Enabled.

        .DESCRIPTION
            This command helps you to quickly toggle you Conditional Access policies between Report-only and Enabled.

            If will skip any policies in Disabled state.

            You must filter the toggle with a prefix filter to only modify specific policies. This is a built-in safety measure.

        .PARAMETER PrefixFilter
            Only toggle the policies with this prefix.

        .PARAMETER SetToReportOnly
            Modify all specified Conditional Access policies to report-only.

        .PARAMETER SetToEnabled
            Modify all specified Conditional Access policies to Enabled.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            Set-DCConditionalAccessPoliciesReportOnlyMode -PrefixFilter 'GLOBAL - ' -SetToReportOnly

        .EXAMPLE
            Set-DCConditionalAccessPoliciesReportOnlyMode -PrefixFilter 'GLOBAL - ' -SetToEnabled
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $true)]
        [string]$PrefixFilter,

        [parameter(Mandatory = $false)]
        [switch]$SetToReportOnly,

        [parameter(Mandatory = $false)]
        [switch]$SetToEnabled
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


    # Parameter check:
    if ($SetToReportOnly -and $SetToEnabled)  {
        Write-Error -Message 'You can''t use -SetToReportOnly and -SetToEnabled at the same time!'
        return
    } elseif (!($SetToReportOnly) -and !($SetToEnabled)) {
        Write-Error -Message 'You must use -SetToReportOnly or -SetToEnabled!'
        return
    }


    if ($SetToEnabled) {
        # Prompt for confirmation:
        $title    = 'Confirm'
        $question = "Do you want to switch all Conditional Access policies with prefix '$PrefixFilter' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )' from Report-only to Enabled?"
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
        $question = "Do you want to switch all Conditional Access policies with prefix '$PrefixFilter' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )' from Enabled to Report-only?"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    }


    # Modify all existing policies.
    Write-Verbose -Verbose -Message "Looking for Conditional Access policies to toggle..."
    $ExistingPolicies = Get-MgIdentityConditionalAccessPolicy


    foreach ($Policy in $ExistingPolicies) {
        if ($Policy.DisplayName.StartsWith($PrefixFilter)) {

            if ($SetToEnabled) {
                if ($Policy.State -eq 'enabledForReportingButNotEnforced') {
                    Write-Verbose -Verbose -Message "Toggling '$($Policy.DisplayName)' to Enabled..."

                    # Toggle policy:
                    $params = @{
                        State = "enabled"
                    }

                    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -BodyParameter $params

                    Start-Sleep -Seconds 1
                }
            } elseif ($SetToReportOnly) {
                if ($Policy.State -eq 'Enabled') {
                    Write-Verbose -Verbose -Message "Toggling '$($Policy.DisplayName)' to Report-only..."

                    # Toggle policy:
                    $params = @{
                        State = "enabledForReportingButNotEnforced"
                    }

                    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -BodyParameter $params

                    Start-Sleep -Seconds 1
                }
            }
        }
    }


    Write-Verbose -Verbose -Message "Done!"
}