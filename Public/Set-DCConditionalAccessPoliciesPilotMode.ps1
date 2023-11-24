function Set-DCConditionalAccessPoliciesPilotMode {
    <#
        .SYNOPSIS
            Toggles Conditional Access policies between 'All users' and a specified pilot group.

        .DESCRIPTION
            This command helps you to quickly toggle you Conditional Access policies between a pilot and production. It does this by switching policies targeting a specified pilot group and 'All users'.

            It is common to use a dedicated Entra ID security group to target specific pilot users during a Conditional Access deployment project. When the pilot is completed you want to move away from that pilot group and target 'All users' in the organization instead (at least with your global baseline).

            You must filter the toggle with a prefix filter to only modify specific policies. Use a prefix like "GLOBAL -" or "PILOT -" for easy bulk management. This is a built-in safety measure.

        .PARAMETER PrefixFilter
            Only toggle the policies with this prefix.

        .PARAMETER PilotGroupName
            The name of your pilot group in Entra ID (must be a security group for users).

        .PARAMETER EnablePilot
            Modify all specified Conditional Access policies to target your pilot group.

        .PARAMETER EnableProduction
            Modify all specified Conditional Access policies to target 'All users'.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            Set-DCConditionalAccessPoliciesPilotMode -PrefixFilter 'GLOBAL - ' -PilotGroupName 'Conditional Access Pilot' -EnablePilot

        .EXAMPLE
            Set-DCConditionalAccessPoliciesPilotMode -PrefixFilter 'GLOBAL - ' -PilotGroupName 'Conditional Access Pilot' -EnableProduction
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $true)]
        [string]$PrefixFilter,

        [parameter(Mandatory = $true)]
        [string]$PilotGroupName,

        [parameter(Mandatory = $false)]
        [switch]$EnablePilot,

        [parameter(Mandatory = $false)]
        [switch]$EnableProduction
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
    if ($EnablePilot -and $EnableProduction)  {
        Write-Error -Message 'You can''t use -EnablePilot and -EnableProduction at the same time!'
        return
    } elseif (!($EnablePilot) -and !($EnableProduction)) {
        Write-Error -Message 'You must use -EnablePilot or -EnableProduction!'
        return
    }


    if ($EnableProduction) {
        # Prompt for confirmation:
        $title    = 'Confirm'
        $question = "Do you want to switch all Conditional Access policies with prefix '$PrefixFilter' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )' from pilot group '$PilotGroupName' to 'All users'?"
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
        $question = "Do you want to switch all Conditional Access policies with prefix '$PrefixFilter' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )' from 'All users' to pilot group '$PilotGroupName'?"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    }


    # Check for existing group.
    Write-Verbose -Verbose -Message "Checking for existing pilot group '$PilotGroupName'..."
    $ExistingPilotGroup = Get-MgGroup -Filter "DisplayName eq '$PilotGroupName'" -Top 1

    if ($ExistingPilotGroup) {
        Write-Verbose -Verbose -Message "Found group '$PilotGroupName'!"
    } else {
        Write-Error -Message "Could not find group '$PilotGroupName'!"
        return
    }


    # Modify all existing policies.
    Write-Verbose -Verbose -Message "Looking for Conditional Access policies to toggle..."
    $ExistingPolicies = Get-MgIdentityConditionalAccessPolicy


    foreach ($Policy in $ExistingPolicies) {
        if ($Policy.DisplayName.StartsWith($PrefixFilter)) {

            if ($EnableProduction) {
                if ($Policy.Conditions.Users.IncludeGroups -contains $ExistingPilotGroup.Id) {
                    Write-Verbose -Verbose -Message "Toggling '$($Policy.DisplayName)' to 'All users'..."

                    # Toggle policy:
                    $params = @{
                        Conditions = @{
                            Users = @{
                                IncludeUsers = @(
                                    "All"
                                )
                            }
                        }
                    }

                    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -BodyParameter $params

                    Start-Sleep -Seconds 1
                }
            } elseif ($EnablePilot) {
                if ($Policy.Conditions.Users.IncludeUsers -eq 'All') {
                    Write-Verbose -Verbose -Message "Toggling '$($Policy.DisplayName)' to pilot group..."

                    # Toggle policy:
                    $params = @{
                        Conditions = @{
                            Users = @{
                                IncludeUsers = @(
                                    "None"
                                )
                                IncludeGroups = @(
                                    "$($ExistingPilotGroup.Id)"
                                )
                            }
                        }
                    }

                    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -BodyParameter $params

                    Start-Sleep -Seconds 1
                }
            }
        }
    }


    Write-Verbose -Verbose -Message "Done!"
}
