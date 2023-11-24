function Export-DCConditionalAccessPolicyDesign {
    <#
        .SYNOPSIS
            Export all Conditional Access policies to JSON.

        .DESCRIPTION
            This CMDlet uses Microsoft Graph to export all Conditional Access policies in the tenant to a JSON file. This JSON file can be used for backup, documentation or to deploy the same policies again with Import-DCConditionalAccessPolicyDesign. You can basically treat Conditional Access as code!

            The user running this CMDlet (the one who signs in when the authentication pops up) must have the appropriate permissions in Entra ID (Global Admin, Security Admin, Conditional Access Admin, etc).

        .PARAMETER FilePath
            The file path where the new JSON file will be created. Skip this to use the current path.

        .PARAMETER PrefixFilter
            Only export the policies with this prefix.

        .INPUTS
            None

        .OUTPUTS
            JSON file with all Conditional Access policies.

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            Export-DCConditionalAccessPolicyDesign

        .EXAMPLE
            $Parameters = @{
                FilePath = 'C:\Temp\Conditional Access.json'
            }
            Export-DCConditionalAccessPolicyDesign @Parameters

        .EXAMPLE
            $Parameters = @{
                FilePath = 'C:\Temp\Conditional Access.json'
                PrefixFilter = 'GLOBAL - '
            }
            Export-DCConditionalAccessPolicyDesign @Parameters
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $false)]
        [string]$FilePath = "$((Get-Location).Path)\Conditional Access Backup $(Get-Date -Format 'yyyy-MM-dd').json",

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
    Connect-DCMsGraphAsUser -Scopes 'Policy.Read.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All' -Verbose


    # Show filter settings.
    if ($PrefixFilter) {
        Write-Verbose -Verbose -Message "Prefix filter was set and only policies beginning with '$PrefixFilter' will be exported!"
    }


    # Export all Conditional Access policies from Microsoft Graph as JSON.
    Write-Verbose -Verbose -Message "Exporting Conditional Access policies to '$FilePath'..."

    $ConditionalAccessPolicies = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies').value

    $Result = foreach ($Policy in $ConditionalAccessPolicies) {
        if ($Policy.DisplayName.StartsWith($PrefixFilter)) {
            Write-Verbose -Verbose -Message "Exporting $($Policy.DisplayName)..."

            $Policy.Id = 'REMOVETHISLINE'

            if ($Policy.GrantControls.authenticationStrength) {
                $params = @{
                    id = [string]$Policy.GrantControls.authenticationStrength.id
                }

                $Policy.GrantControls.authenticationStrength = $params
            }

            $Policy
        }
    }

    $Result | ConvertTo-Json -Depth 10 | Out-File -Force:$true -FilePath $FilePath


    # Perform some clean up in the JSON file.
    $CleanUp = Get-Content $FilePath | Select-String -Pattern '"REMOVETHISLINE"', '"createdDateTime":', '"modifiedDateTime":', 'authenticationStrength@odata.context' -NotMatch

    $CleanUp | Out-File -Force:$true -FilePath $FilePath


    Write-Verbose -Verbose -Message "Done!"
}
