function Get-DCNamedLocations {
    <#
        .SYNOPSIS
            List Named Locations in the tenant.

        .DESCRIPTION
            List Named Locations in the tenant.

            You can filter on a name prefix with -PrefixFilter.

        .PARAMETER PrefixFilter
            Only show the named locations with this prefix.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            Get-DCNamedLocations

        .EXAMPLE
            Get-DCNamedLocations -PrefixFilter 'OFFICE-'

        .EXAMPLE
            # List all trusted IP addresses.
            (Get-DCNamedLocations | where isTrusted -eq $true).ipRanges | Select-Object -Unique | Sort-Object

        .EXAMPLE
            # List all countries.
            (Get-DCNamedLocations).countriesAndRegions | Select-Object -Unique | Sort-Object
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


    # Get all named locations.
    $NamedLocations = Get-MgIdentityConditionalAccessNamedLocation

    Write-Verbose -Verbose -Message "Fetching Named Locations..."

    $Result = foreach ($NamedLocation in $NamedLocations) {
        if ($NamedLocation.DisplayName.StartsWith($PrefixFilter)) {
            $CustomObject = New-Object -TypeName psobject
            $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value $NamedLocation.DisplayName
            $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value $NamedLocation.Id
            $CustomObject | Add-Member -MemberType NoteProperty -Name "CreatedDateTime" -Value $NamedLocation.CreatedDateTime
            $CustomObject | Add-Member -MemberType NoteProperty -Name "ModifiedDateTime" -Value $NamedLocation.ModifiedDateTime
            $CustomObject | Add-Member -MemberType NoteProperty -Name "isTrusted" -Value $NamedLocation.AdditionalProperties.isTrusted
            $CustomObject | Add-Member -MemberType NoteProperty -Name "ipRanges" -Value $NamedLocation.AdditionalProperties.ipRanges.cidrAddress
            $CustomObject | Add-Member -MemberType NoteProperty -Name "countriesAndRegions" -Value $NamedLocation.AdditionalProperties.countriesAndRegions
            $CustomObject | Add-Member -MemberType NoteProperty -Name "countryLookupMethod" -Value $NamedLocation.AdditionalProperties.countryLookupMethod
            $CustomObject | Add-Member -MemberType NoteProperty -Name "includeUnknownCountriesAndRegions" -Value $NamedLocation.AdditionalProperties.includeUnknownCountriesAndRegions
            $CustomObject
        }
    }

    $Result


    Write-Verbose -Verbose -Message "Done!"
}
