function Import-DCConditionalAccessPolicyDesign {
    <#
        .SYNOPSIS
            Import Conditional Access policies from JSON.

        .DESCRIPTION
            This CMDlet uses Microsoft Graph to automatically create Conditional Access policies from a JSON file.

            The JSON file can be created from existing policies with Export-DCConditionalAccessPolicyDesign or manually by following the syntax described in the Microsoft Graph documentation:
            https://docs.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-1.0

            All Conditional Access policies created by this CMDlet will be set to report-only mode if you don't use the -SkipReportOnlyMode override.

            WARNING: If you want to, you can also delete all existing policies when deploying your new ones with -DeleteAllExistingPolicies, Use this parameter with caution and always create a backup with Export-DCConditionalAccessPolicyDesign first!

            The user running this CMDlet (the one who signs in when the authentication pops up) must have the appropriate permissions in Entra ID (Global Admin, Security Admin, Conditional Access Admin, etc).

            As a best practice you should always have an Entra ID security group with break glass accounts excluded from all Conditional Access policies.

        .PARAMETER FilePath
            The file path of the JSON file containing your Conditional Access policies.

        .PARAMETER SkipReportOnlyMode
            All Conditional Access policies created by this CMDlet will be set to report-only mode if you don't use this parameter.

        .PARAMETER DeleteAllExistingPolicies
            WARNING: If you want to, you can delete all existing policies when deploying your new ones with -DeleteAllExistingPolicies, Use this parameter with causon and allways create a backup with Export-DCConditionalAccessPolicyDesign first!!

        .PARAMETER AddCustomPrefix
            Adds a custom prefix to all policy names.

        .PARAMETER PrefixFilter
            Only import (and delete) the policies with this prefix in the JSON file.

        .INPUTS
            JSON file containing your Conditional Access policies.

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            $Parameters = @{
                FilePath = 'C:\Temp\Conditional Access.json'
                SkipReportOnlyMode = $false
                DeleteAllExistingPolicies = $false
            }

            Import-DCConditionalAccessPolicyDesign @Parameters

        .EXAMPLE
            $Parameters = @{
                FilePath = 'C:\Temp\Conditional Access.json'
                SkipReportOnlyMode = $false
                DeleteAllExistingPolicies = $false
                AddCustomPrefix = 'PILOT - '
            }

            Import-DCConditionalAccessPolicyDesign @Parameters

        .EXAMPLE
            $Parameters = @{
                FilePath = 'C:\Temp\Conditional Access.json'
                SkipReportOnlyMode = $true
                DeleteAllExistingPolicies = $true
                PrefixFilter = 'GLOBAL - '
            }

            Import-DCConditionalAccessPolicyDesign @Parameters
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $true)]
        [string]$FilePath,

        [parameter(Mandatory = $false)]
        [switch]$SkipReportOnlyMode,

        [parameter(Mandatory = $false)]
        [switch]$DeleteAllExistingPolicies,

        [parameter(Mandatory = $false)]
        [string]$AddCustomPrefix = '',

        [parameter(Mandatory = $false)]
        [string]$PrefixFilter
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


    # Prompt for confirmation:
    if ($SkipReportOnlyMode) {
        $title    = 'Confirm'
        $question = "Do you want to import the Conditional Access policies from JSON file '$FilePath' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )'? WARNING: ALL POLICIES will go live for ALL USERS! Remove -SkipReportOnlyMode to deploy in report-only mode instead."
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
            Write-Verbose -Verbose -Message "Starting deployment..."
        } else {
            return
        }
    } else {
        $title    = 'Confirm'
        $question = "Do you want to import the Conditional Access policies from JSON file '$FilePath' in report-only mode in tenant '$(((Get-MgContext).Account.Split('@'))[1] )'?"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 0)
        if ($decision -eq 0) {
            Write-Host ""
            Write-Verbose -Verbose -Message "Starting deployment..."
        } else {
            return
        }
    }


    # Show filter settings.
    if ($PrefixFilter) {
        Write-Verbose -Verbose -Message "Prefix filter was set and only policies beginning with '$PrefixFilter' will be affected!"
    }


    # Import policies from JSON file.
    Write-Verbose -Verbose -Message "Importing JSON from '$FilePath'..."
    $ConditionalAccessPolicies = Get-Content -Raw -Path $FilePath


    # Modify enabled policies to report-only if not skipped with -SkipReportOnlyMode.
    if (!($SkipReportOnlyMode)) {
        Write-Verbose -Verbose -Message "Setting new policies to report-only mode..."
        $ConditionalAccessPolicies = $ConditionalAccessPolicies -replace '"enabled"', '"enabledForReportingButNotEnforced"'
    }


    # Add prefix.
    $ConditionalAccessPolicies = $ConditionalAccessPolicies -replace '"displayName": "', """displayName"": ""$AddCustomPrefix"


    # Delete all existing policies if -DeleteAllExistingPolicies is specified.
    if ($DeleteAllExistingPolicies) {
        Write-Verbose -Verbose -Message "Deleting existing Conditional Access policies..."
        $GraphUri = 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies'
        $ExistingPolicies = Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri -ErrorAction SilentlyContinue

        foreach ($Policy in $ExistingPolicies) {
            if ($Policy.displayName.StartsWith($PrefixFilter)) {
                Start-Sleep -Seconds 1
                $GraphUri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($Policy.id)"

                Invoke-MgGraphRequest -AccessToken $AccessToken -GraphMethod 'DELETE' -GraphUri $GraphUri -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }


    $ConditionalAccessPolicies = $ConditionalAccessPolicies | ConvertFrom-Json

    foreach ($Policy in $ConditionalAccessPolicies) {
        if ($Policy.displayName.StartsWith($PrefixFilter)) {
            Start-Sleep -Seconds 1
            Write-Verbose -Verbose -Message "Creating '$($Policy.DisplayName)'..."

            try {
                # Create new policies.
                Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Body ($Policy | ConvertTo-Json -Depth 10) | Out-Null
            }
            catch {
                Write-Error -Message $_.Exception.Message -ErrorAction Continue
            }
        }
    }


    Write-Verbose -Verbose -Message "Done!"
}