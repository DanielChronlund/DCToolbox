function Get-DCConditionalAccessPolicies {
    <#
        .SYNOPSIS
            List all Conditional Access policies in the tenant.

        .DESCRIPTION
            List all Conditional Access policies in the tenant.

            You can filter on a name prefix with -PrefixFilter.

        .PARAMETER PrefixFilter
            Only show the policies with this prefix.

        .PARAMETER ShowTargetResources
            Show included and excluded resources in output. Only relevant without -Details.

        .PARAMETER Details
            Include policy details in output.

        .PARAMETER NamesOnly
            Show names only in output.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            Get-DCConditionalAccessPolicies

        .EXAMPLE
            Get-DCConditionalAccessPolicies -PrefixFilter 'GLOBAL - '
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $false)]
        [string]$PrefixFilter = '',

        [parameter(Mandatory = $false)]
        [switch]$ShowTargetResources,

        [parameter(Mandatory = $false)]
        [switch]$Details,

        [parameter(Mandatory = $false)]
        [switch]$NamesOnly
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


    # Get all existing policies.
    $ExistingPolicies = Get-MgIdentityConditionalAccessPolicy

    Write-Verbose -Verbose -Message "Fetching Conditional Access policies..."

    if ($Details) {
        $Result = foreach ($Policy in $ExistingPolicies) {
            if ($Policy.DisplayName.StartsWith($PrefixFilter)) {
                $CustomObject = New-Object -TypeName psobject
                $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value $Policy.DisplayName
                $CustomObject | Add-Member -MemberType NoteProperty -Name "State" -Value $Policy.State
                $CustomObject | Add-Member -MemberType NoteProperty -Name "CreatedDateTime" -Value $Policy.CreatedDateTime
                $CustomObject | Add-Member -MemberType NoteProperty -Name "ModifiedDateTime" -Value $Policy.ModifiedDateTime
                $CustomObject | Add-Member -MemberType NoteProperty -Name "Conditions" -Value ($Policy.Conditions | ConvertTo-Json)
                $CustomObject | Add-Member -MemberType NoteProperty -Name "GrantControls" -Value ($Policy.GrantControls | ConvertTo-Json)
                $CustomObject | Add-Member -MemberType NoteProperty -Name "SessionControls" -Value ($Policy.SessionControls | ConvertTo-Json)
                $CustomObject
            }
        }

        $Result | Format-List
    } elseif ($NamesOnly) {
        $Result = foreach ($Policy in $ExistingPolicies) {
            if ($Policy.DisplayName.StartsWith($PrefixFilter)) {
                $CustomObject = New-Object -TypeName psobject
                $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value $Policy.DisplayName
                $CustomObject
            }
        }

        $Result
    } else {
        $Result = foreach ($Policy in $ExistingPolicies) {
            if ($Policy.DisplayName.StartsWith($PrefixFilter)) {
                $CustomObject = New-Object -TypeName psobject
                $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value $Policy.DisplayName
                $CustomObject | Add-Member -MemberType NoteProperty -Name "State" -Value $Policy.State
                $CustomObject | Add-Member -MemberType NoteProperty -Name "CreatedDateTime" -Value $Policy.CreatedDateTime
                $CustomObject | Add-Member -MemberType NoteProperty -Name "ModifiedDateTime" -Value $Policy.ModifiedDateTime

                if ($ShowTargetResources) {
                    $CustomObject | Add-Member -MemberType NoteProperty -Name "TargetResources" -Value ($Policy.Conditions.Users | ConvertTo-Json -Depth 5)
                }

                $CustomObject
            }
        }


        if ($ShowTargetResources) {
            $Result | Format-List
        } else {
            $Result | Format-Table
        }
    }


    Write-Verbose -Verbose -Message "Done!"
}
