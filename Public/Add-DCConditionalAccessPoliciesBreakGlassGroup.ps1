function Add-DCConditionalAccessPoliciesBreakGlassGroup {
    <#
        .SYNOPSIS
            Excludes a specified Entra ID security group from all Conditional Access policies in the tenant.

        .DESCRIPTION
            Excludes a specified Entra ID security group from all Conditional Access policies in the tenant.

            Please create the group and add your break glass accounts before running this command.

            You can filter on a name prefix with -PrefixFilter.

        .PARAMETER PrefixFilter
            Only modify the policies with this prefix.

        .PARAMETER ExcludeGroupName
            The name of your exclude group in Entra ID. Please create the group and add your break glass accounts before running this command.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            Add-DCConditionalAccessPoliciesBreakGlassGroup -PrefixFilter 'GLOBAL - ' -ExcludeGroupName 'Excluded from Conditional Access'
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $false)]
        [string]$PrefixFilter = '',

        [parameter(Mandatory = $true)]
        [string]$ExcludeGroupName
    )


    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Check PowerShell version.
    Confirm-DCPowerShellVersion -Verbose


    # Check Microsoft Graph PowerShell module.
    Install-DCMicrosoftGraphPowerShellModule -Verbose


    # Connect to Microsoft Graph.
    Connect-DCMsGraphAsUser -Scopes 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All', 'Group.Read.All' -Verbose


    # Prompt for confirmation:
    $title    = 'Confirm'
    $question = "Do you want to exclude the group '$($ExcludeGroupName)' from all Conditional Access policies with prefix '$PrefixFilter' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )'?"
    $choices  = '&Yes', '&No'

    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 0)
    if ($decision -eq 0) {
        Write-Host ""
    } else {
        return
    }


    # Check for existing group.
    Write-Verbose -Verbose -Message "Checking for existing exclude group '$ExcludeGroupName'..."
    $ExistingExcludeGroup = Get-MgGroup -Filter "DisplayName eq '$ExcludeGroupName'" -Top 1

    if ($ExistingExcludeGroup) {
        Write-Verbose -Verbose -Message "Found group '$ExcludeGroupName'!"
    } else {
        Write-Error -Message "Could not find group '$ExcludeGroupName'!"
        return
    }


    # Modify all existing policies.
    Write-Verbose -Verbose -Message "Looking for Conditional Access policies to modify..."
    $ExistingPolicies = Get-MgIdentityConditionalAccessPolicy


    foreach ($Policy in $ExistingPolicies) {
        if ($Policy.DisplayName.StartsWith($PrefixFilter)) {
            Write-Verbose -Verbose -Message "Excluding group '$ExcludeGroupName' from '$($Policy.DisplayName)'..."

            # Toggle policy:
            $params = @{
                Conditions = @{
                    Users = @{
                        ExcludeGroups = @(
                            $Policy.Conditions.Users.ExcludeGroups
                            "$($ExistingExcludeGroup.Id)"
                        )
                    }
                }
            }

            Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -BodyParameter $params

            Start-Sleep -Seconds 1
        }
    }


    Write-Verbose -Verbose -Message "Done!"
}