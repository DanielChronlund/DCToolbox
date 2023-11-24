function Invoke-DCHuntingQuery {
    <#
        .SYNOPSIS
            Connect to Microsoft Graph with the Microsoft Graph PowerShell module and run a KQL hunting query in Microsoft Defender XDR.

        .DESCRIPTION
            Connect to Microsoft Graph with the Microsoft Graph PowerShell module and run a KQL hunting query in Microsoft Defender XDR.

        .PARAMETER Query
            The KQL query you want to run in Microsoft Defender XDR.

        .PARAMETER IncludeQueryAtTop
            Include the KQL query before the actual result output.

        .PARAMETER IncludeRaw
            Include the raw formated and escaped KQL query sent to Microsoft Graph.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            $Query = @'
            DeviceEvents
            | where ActionType startswith "Asr"
            | summarize count() by ActionType
            | order by count_
            '@

            Invoke-DCHuntingQuery -Query $Query

        .EXAMPLE
            $Query = @'
            DeviceEvents
            | where ActionType startswith "Asr"
            | summarize count() by ActionType
            | order by count_
            '@

            Invoke-DCHuntingQuery -Query $Query -IncludeKQLQueryAtTop
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [string]$Query,

        [parameter(Mandatory = $false)]
        [switch]$IncludeKQLQueryAtTop,

        [parameter(Mandatory = $false)]
        [switch]$IncludeRaw
    )


    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Check PowerShell version.
    Confirm-DCPowerShellVersion


    # Check Microsoft Graph PowerShell module.
    Install-DCMicrosoftGraphPowerShellModule


    # Connect to Microsoft Graph.
    Connect-DCMsGraphAsUser -Scopes 'ThreatHunting.Read.All'


    if ($IncludeKQLQueryAtTop) {
        Write-Host ''
        Write-Host -ForegroundColor Cyan $Query
        Write-Host ''
    }


    # Run KQL hunting query.
    $Query = $Query -replace "\\", '\\' -replace '"', '\"'

    $GraphBody = @"
{
    "Query": "$Query"
}
"@

    if ($IncludeRaw) {
        Write-Host ''
        Write-Host -ForegroundColor Magenta $Query
        Write-Host ''
    }

    $Results = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Body $GraphBody -OutputType Json

    $Results = ($Results | ConvertFrom-Json).results

    $Properties = @(($Results | Select-Object -First 1).PSObject.Properties | Where-Object { $_.Name -notlike "*@odata.type"}).Name

    $CountIsPresent = $false

    [string[]]$Properties = foreach ($Property in $Properties) {
        if ($Property -eq 'count_') {
            $CountIsPresent = $true
        } else {
            $Property
        }
    }

    if ($CountIsPresent) {
        $Properties += "count_"
    }

    $Results | Select-Object -Property $Properties

    if (!($Results)) {
        Write-host '-- empty result --'
        Write-host ''
    }
}