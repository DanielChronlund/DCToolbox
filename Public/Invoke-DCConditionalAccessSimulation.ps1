function Invoke-DCConditionalAccessSimulation {
    <#
        .SYNOPSIS
            Simulates the Entra ID Conditional Access evaluation process of a specific scenario.

        .DESCRIPTION
            Uses Microsoft Graph to fetch all Entra ID Conditional Access policies. It then evaluates which policies that would have been applied if this was a real sign-in to Entra ID. Use the different parameters available to specify the conditions. Details are included under each parameter.

        .PARAMETER UserPrincipalName
            The UPN of the simulated Entra ID user signing in. Can also be set to 'All' for all users, or 'GuestsOrExternalUsers' to test external user sign-in scenarios. Example: 'user@example.com'. Default: 'All'.

        .PARAMETER JSONFile
            Only use this parameter if you want to analyze a local JSON file export of Conditional Access polices, instead of a live tenant. Point it to the local JSON file. Export JSON with Export-DCConditionalAccessPolicyDesign (or any other tool exporting Conditional Access policies from Microsoft Graph to JSON), like 'Entra Exporter'.

        .PARAMETER ApplicationDisplayName
            The display name of the application targeted by Conditional Access policies (same display name as in Entra ID Portal when creating Conditional Access policies). Example 1: 'Office 365'. Example 2: 'Microsoft Admin Portals'. Default: 'All'.

        .PARAMETER UserAction
            Under construction...

        .PARAMETER ClientApp
            The client app type used during sign-in. Possible values: 'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'easSupported', 'other'. Default: 'browser'

        .PARAMETER TrustedIPAddress
            Specify if the simulated sign-in comes from a trusted IP address (marked as trusted in Named Locations)? $true or $false? Don't specify the actual IP address. That is not really that important when simulating policy evaluation. Default: $false

        .PARAMETER Country
            The country code for the sign-in country of origin based on IP address geo data. By default, this script tries to resolve the IP address of the current PowerShell session.

        .PARAMETER Platform
            Specify the OS platform of the client signing in. Possible values: 'all', 'android', 'iOS', 'windows', 'windowsPhone', 'macOS', 'linux', 'spaceRocket'. Default: 'windows'

        .PARAMETER SignInRiskLevel
            Specify the Entra ID Protection sign-in risk level. Possible values: 'none', 'low', 'medium', 'high'. Default: 'none'

        .PARAMETER UserRiskLevel
            Specify the Entra ID Protection user risk level. Possible values: 'none', 'low', 'medium', 'high'. Default: 'none'

        .PARAMETER SummarizedOutput
            By default, this script returns PowerShell objects representing all applied Conditional Access policies only. This can be used for piping to other tools, etc. But sometimes you also want a simple answer of what would happen during the simulated policy evaluation. Specify this parameter to add a summarized and simplified output (outputs to 'Informational' stream with Write-Host).

        .PARAMETER VerbosePolicyEvaluation
            Include detailed verbose policy evaluation info. Use for troubleshooting and debugging.

        .PARAMETER IncludeNonMatchingPolicies
            Also, include all policies that did not match, and therefor was not applied. This can be useful to produce different kinds of Conditional Access reports.

        .INPUTS
            None

        .OUTPUTS
            Simulated Conditional Access evaluation results

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            # Run basic evaluation with default settings.
            Invoke-DCConditionalAccessSimulation | Format-List

        .EXAMPLE
            # Run evaluation with custom settings.
            $Parameters = @{
                UserPrincipalName = 'user@example.com'
                ApplicationDisplayName = 'Office 365'
                ClientApp = 'mobileAppsAndDesktopClients'
                TrustedIPAddress = $true
                Country = 'US'
                Platform = 'windows'
                SignInRiskLevel = 'medium'
                UserRiskLevel = 'high'
                SummarizedOutput = $true
                VerbosePolicyEvaluation = $false
                IncludeNonMatchingPolicies = $false
            }

            Invoke-DCConditionalAccessSimulation @Parameters

        .EXAMPLE
            # Run basic evaluation offline against a JSON of Conditional Access policies.
            Invoke-DCConditionalAccessSimulation -JSONFile 'Conditional Access Backup.json' | Format-List
    #>



    # ----- [Initializations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $false)]
        [string]$JSONFile,

        [parameter(Mandatory = $false)]
        [string]$UserPrincipalName = 'All',

        [parameter(Mandatory = $false)]
        [string]$ApplicationDisplayName = 'All',

        [parameter(Mandatory = $false)]
        [string]$UserAction,

        [parameter(Mandatory = $false)]
        [ValidateSet('browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'easSupported', 'other')]
        [string]$ClientApp = 'browser',

        [parameter(Mandatory = $false)]
        [switch]$TrustedIPAddress,

        [parameter(Mandatory = $false)]
        [ValidateLength(2,2)]
        [string]$Country = ((Get-DCPublicIP).country),

        [parameter(Mandatory = $false)]
        [ValidateSet('all', 'android', 'iOS', 'windows', 'windowsPhone', 'macOS', 'linux', 'spaceRocket')]
        [string]$Platform = 'windows',

        [parameter(Mandatory = $false)]
        [ValidateSet('none', 'low', 'medium', 'high')]
        [string]$SignInRiskLevel = 'none',

        [parameter(Mandatory = $false)]
        [ValidateSet('none', 'low', 'medium', 'high')]
        [string]$UserRiskLevel = 'none',

        [parameter(Mandatory = $false)]
        [switch]$SummarizedOutput,

        [parameter(Mandatory = $false)]
        [switch]$VerbosePolicyEvaluation,

        [parameter(Mandatory = $false)]
        [switch]$IncludeNonMatchingPolicies
    )


    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Check PowerShell version.
    Confirm-DCPowerShellVersion -Verbose


    $Policies = $null

    if ($JSONFile) {
        $Policies = Get-Content -Path $JSONFile | ConvertFrom-Json

        if ($UserPrincipalName -ne 'GuestsOrExternalUsers') {
            $UserPrincipalName = 'All'
        }
    } else {
        # Check Microsoft Graph PowerShell module.
        Install-DCMicrosoftGraphPowerShellModule -Verbose


        # Connect to Microsoft Graph.
        Connect-DCMsGraphAsUser -Scopes 'Policy.Read.ConditionalAccess', 'Policy.Read.All', 'User.Read.All' -Verbose


        # Get all existing policies.
        Write-Verbose -Verbose -Message "Fetching Conditional Access policies..."
        $Policies = Get-MgIdentityConditionalAccessPolicy
    }


    # Set conditions to simulate.

    Write-Verbose -Verbose -Message "Simulating Conditional Access evaluation..."

    $CustomObject = New-Object -TypeName psobject


    # User.
    $UserId = (Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'").Id

    if ($UserId) {
        $CustomObject | Add-Member -MemberType NoteProperty -Name "UserId" -Value $UserId
    } else {
        if ($UserPrincipalName -eq 'GuestsOrExternalUsers') {
            $CustomObject | Add-Member -MemberType NoteProperty -Name "UserId" -Value 'GuestsOrExternalUsers'
        } else {
            $CustomObject | Add-Member -MemberType NoteProperty -Name "UserId" -Value 'All'
        }
    }


    # Groups.
    $Groups = $null

    if ($UserId) {
        $Groups = (Get-MgUserTransitiveMemberOf -UserId $UserId).Id
        $CustomObject | Add-Member -MemberType NoteProperty -Name "Groups" -Value $Groups
    } else {
        $CustomObject | Add-Member -MemberType NoteProperty -Name "Groups" -Value $null
    }


    #Application.
    $AppId = $null
    if ($ApplicationDisplayName -eq 'All') {
        $AppId = 'All'
    } elseif ($ApplicationDisplayName -eq 'Office 365') {
        $AppId = 'Office365'
    } elseif ($ApplicationDisplayName -eq 'Microsoft Admin Portals') {
        $AppId = 'MicrosoftAdminPortals'
    } else {
        $AppId = (Get-MGServicePrincipal -Filter "DisplayName eq '$ApplicationDisplayName'").AppId
    }

    $CustomObject | Add-Member -MemberType NoteProperty -Name "Application" -Value $AppId


    # Client App (all, browser, mobileAppsAndDesktopClients, exchangeActiveSync, easSupported, other).
    $CustomObject | Add-Member -MemberType NoteProperty -Name "ClientApp" -Value $ClientApp


    # IP Address.
    $CustomObject | Add-Member -MemberType NoteProperty -Name "TrustedIPAddress" -Value $TrustedIPAddress


    # Country.
    if ($Country -eq $null) {
        $Country = 'All'
    }

    $CustomObject | Add-Member -MemberType NoteProperty -Name "Country" -Value $Country


    # Platform (android, iOS, windows, windowsPhone, macOS, linux, all, unknownFutureValue).
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Platform" -Value $Platform


    # Sign-in Risk Level (low, medium, high, none).
    $CustomObject | Add-Member -MemberType NoteProperty -Name "SignInRiskLevel" -Value $SignInRiskLevel


    # User Risk Level (low, medium, high, none).
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserRiskLevel" -Value $UserRiskLevel


    $ConditionsToSimulate = $CustomObject


    # Show conditions to test.
    if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message ($ConditionsToSimulate | Format-List | Out-String) }



    # Loop through all Conditional Access policies and test the current conditions.
    $Result = foreach ($Policy in $Policies) {
        if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message "POLICY EVALUATION: $($Policy.DisplayName)" }

        $CustomObject = New-Object -TypeName psobject

        $CustomObject | Add-Member -MemberType NoteProperty -Name "Policy" -Value $Policy.DisplayName

        $GrantControls = $Policy.GrantControls | Select-Object AuthenticationStrength, Operator, BuiltInControls, TermsOfUse, CustomAuthenticationFactors

        try {
            if ($GrantControls.authenticationStrength.id) {
                $GrantControls.authenticationStrength = $true
            } else {
                $GrantControls.authenticationStrength = $false
            }

            $GrantControls = $GrantControls | ConvertTo-Json -Depth 10

            $CustomObject | Add-Member -MemberType NoteProperty -Name "GrantControls" -Value $GrantControls
        } catch {
            $CustomObject | Add-Member -MemberType NoteProperty -Name "GrantControls" -Value $GrantControls
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "SessionControls" -Value ($Policy.SessionControls | Select-Object ApplicationEnforcedRestrictions, CloudAppSecurity, DisableResilienceDefaults, PersistentBrowser, SignInFrequency | ConvertTo-Json)


        $PolicyMatch = $true
        $UserMatch = $false
        $GroupMatch = $false


        #Enabled
        if ($Policy.State -eq 'enabled') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'Enabled: APPLIED' }
        } else {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'Enabled: NOT APPLIED' }
            $PolicyMatch = $false
        }


        #ApplicationFilter


        # ExcludeApplications:
        if ($Policy.Conditions.Applications.ExcludeApplications -contains $ConditionsToSimulate.Application) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludeApplications: NOT APPLIED' }
            $PolicyMatch = $false
        } else {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludeApplications: APPLIED' }
        }


        #IncludeApplications
        if ($Policy.Conditions.Applications.IncludeApplications -eq 'All') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeApplications: APPLIED' }
        } elseif ($Policy.Conditions.Applications.IncludeApplications -eq 'none') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeApplications: NOT APPLIED' }
            $PolicyMatch = $false
        } elseif ($Policy.Conditions.Applications.IncludeApplications -notcontains $ConditionsToSimulate.Application) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeApplications: NOT APPLIED' }
            $PolicyMatch = $false
        } else {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeApplications: APPLIED' }
        }


        #IncludeUserActions
        #


        #ClientAppTypes
        if ($Policy.Conditions.ClientAppTypes -eq 'all') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ClientAppTypes: APPLIED' }
        } elseif ($Policy.Conditions.ClientAppTypes -notcontains $ConditionsToSimulate.ClientApp) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ClientAppTypes: NOT APPLIED' }
            $PolicyMatch = $false
        } else {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ClientAppTypes: APPLIED' }
        }


        #DeviceFilter
        #


        #ExcludeLocationsIPAddress
        if ($ConditionsToSimulate.TrustedIPAddress) {
            $TrustedLocation = foreach ($Location in $Policy.Conditions.Locations.ExcludeLocations) {
                if (!($JSONFile)) {
                    (Get-MgIdentityConditionalAccessNamedLocation | where id -eq $Location).AdditionalProperties.isTrusted
                }
            }

            if ($TrustedLocation) {
                if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludeLocationsIPAddress: NOT APPLIED' }
                $PolicyMatch = $false
            } else {
                if ($JSONFile) {
                    if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludeLocationsIPAddress: APPLIED (JSON mode assumes not excluded)' }
                } else {
                    if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludeLocationsIPAddress: APPLIED' }
                }
            }
        } else {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludeLocationsIPAddress: APPLIED' }
        }


        #ExcludeLocationsCountry
        $TrustedLocation = foreach ($Location in $Policy.Conditions.Locations.ExcludeLocations) {
            if (!($JSONFile)) {
                (Get-MgIdentityConditionalAccessNamedLocation | where id -eq $Location).AdditionalProperties.countriesAndRegions
            }
        }

        if ($TrustedLocation -contains $ConditionsToSimulate.Country) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludeLocationsCountry: NOT APPLIED' }
            $PolicyMatch = $false
        } else {
            if ($JSONFile -and $Policy.Conditions.Locations.ExcludeLocations) {
                if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludeLocationsCountry: NOT APPLIED (JSON mode assumes excluded)' }
                $PolicyMatch = $false
            } else {
                if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludeLocationsCountry: APPLIED' }
            }
        }


        #IncludeLocationsIPAddress
        $IncludeLocationsIPAddressMatch = $true
        if ($Policy.Conditions.Locations.IncludeLocations -eq $null) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeLocationsIPAddress: APPLIED' }
        } elseif ($Policy.Conditions.Locations.IncludeLocations -eq 'All') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeLocationsIPAddress: APPLIED' }
        } elseif ($Policy.Conditions.Locations.IncludeLocations -eq 'AllTrusted' -and $ConditionsToSimulate.TrustedIPAddress) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeLocationsIPAddress: APPLIED' }
        } else {
            $TrustedLocation = foreach ($Location in $Policy.Conditions.Locations.IncludeLocations) {
                if (!($JSONFile)) {
                    (Get-MgIdentityConditionalAccessNamedLocation | where id -eq $Location).AdditionalProperties.isTrusted
                }
            }

            if ($TrustedLocation) {
                if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeLocationsIPAddress: APPLIED' }
            } else {
                if ($JSONFile) {
                    if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeLocationsIPAddress: APPLIED (JSON mode assumes included)' }
                } else {
                    if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeLocationsIPAddress: NOT APPLIED' }
                    $IncludeLocationsIPAddressMatch = $false
                }
            }
        }


        #IncludeLocationsCountry
        $IncludeLocationsCountryMatch = $true
        if ($Policy.Conditions.Locations.IncludeLocations -eq $null) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeLocationsCountry: APPLIED' }
        } elseif ($Policy.Conditions.Locations.IncludeLocations -eq 'All') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeLocationsCountry: APPLIED' }
        } elseif ($Policy.Conditions.Locations.IncludeLocations -eq 'AllTrusted') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeLocationsCountry: APPLIED' }
        } else {
            $TrustedLocation = foreach ($Location in $Policy.Conditions.Locations.IncludeLocations) {
                if (!($JSONFile)) {
                    (Get-MgIdentityConditionalAccessNamedLocation | where id -eq $Location).AdditionalProperties.countriesAndRegions
                }
            }

            if ($TrustedLocation -contains $ConditionsToSimulate.Country) {
                if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeLocationsCountry: APPLIED' }
            } else {
                if ($JSONFile) {
                    if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeLocationsCountry: APPLIED (JSON mode assumes included)' }
                } else {
                    if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeLocationsCountry: NOT APPLIED' }
                    $IncludeLocationsCountryMatch = $false
                }
            }
        }

        if ($IncludeLocationsIPAddressMatch -eq $false -and $IncludeLocationsCountryMatch -eq $false) {
            $PolicyMatch = $false
        }


        #ExcludePlatforms
        if (($Policy.Conditions.Platforms.ExcludePlatforms).Count -eq 0) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludePlatforms: APPLIED' }
        } elseif ($Policy.Conditions.Platforms.ExcludePlatforms -eq 'all') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludePlatforms: NOT APPLIED' }
            $PolicyMatch = $false
        } elseif ($Policy.Conditions.Platforms.ExcludePlatforms -contains $ConditionsToSimulate.Platform) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludePlatforms: NOT APPLIED' }
            $PolicyMatch = $false
        } else {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludePlatforms: APPLIED' }
        }


        #IncludePlatforms
        if (($Policy.Conditions.Platforms.IncludePlatforms).Count -eq 0) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludePlatforms: APPLIED' }
        } elseif ($Policy.Conditions.Platforms.IncludePlatforms -eq 'all') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludePlatforms: APPLIED' }
        } elseif ($Policy.Conditions.Platforms.IncludePlatforms -contains $ConditionsToSimulate.Platform) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludePlatforms: APPLIED' }
        } else {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludePlatforms: NOT APPLIED' }
            $PolicyMatch = $false
        }


        #SignInRiskLevels
        if (($Policy.Conditions.SignInRiskLevels).Count -eq 0) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'SignInRiskLevels: APPLIED' }
        } elseif ($Policy.Conditions.SignInRiskLevels -notcontains $ConditionsToSimulate.SignInRiskLevel) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'SignInRiskLevels: NOT APPLIED' }
            $PolicyMatch = $false
        }


        #UserRiskLevels
        if (($Policy.Conditions.UserRiskLevels).Count -eq 0) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'UserRiskLevels: APPLIED' }
        } elseif ($Policy.Conditions.UserRiskLevels -notcontains $ConditionsToSimulate.UserRiskLevel) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'UserRiskLevels: NOT APPLIED' }
            $PolicyMatch = $false
        }


        #ExcludeGroups
        $ExcludeGroupsResult = 'ExcludeGroups: APPLIED'

        if (($Policy.Conditions.Users.ExcludeGroups).Count -eq 0) {
            #
        } else {
            foreach ($Group in $Policy.Conditions.Users.ExcludeGroups) {
                if ($ConditionsToSimulate.Groups -contains $Group) {
                    $ExcludeGroupsResult = 'ExcludeGroups: NOT APPLIED'
                    break
                }
            }
        }

        if ($ExcludeGroupsResult -eq 'ExcludeGroups: APPLIED') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message $ExcludeGroupsResult }
        } else {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message $ExcludeGroupsResult }
            $PolicyMatch = $false
        }


        #IncludeGroups
        $IncludeGroupsResult = 'IncludeGroups: NOT APPLIED'

        if (($Policy.Conditions.Users.IncludeGroups).Count -eq 0) {
            #
        } else {
            foreach ($Group in $Policy.Conditions.Users.IncludeGroups) {
                if ($ConditionsToSimulate.Groups -contains $Group) {
                    $IncludeGroupsResult = 'IncludeGroups: APPLIED'
                    break
                }
            }
        }

        if ($IncludeGroupsResult -eq 'IncludeGroups: NOT APPLIED') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message $IncludeGroupsResult }
            $GroupMatch = $false
        } else {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message $IncludeGroupsResult }
            $GroupMatch = $true
        }


        #ExcludeGuestsOrExternalUsers
        #IncludeGuestsOrExternalUsers
        #ExcludeRoles
        #IncludeRoles


        #ExcludeUsers
        if ($Policy.Conditions.Users.excludeGuestsOrExternalUsers.GuestOrExternalUserTypes -and $ConditionsToSimulate.UserId -eq 'GuestsOrExternalUsers') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludeUsers: NOT APPLIED' }
            $UserMatch = $false
        } elseif ($Policy.Conditions.Users.ExcludeUsers -contains $ConditionsToSimulate.UserId) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludeUsers: NOT APPLIED' }
            $PolicyMatch = $false
        } else {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'ExcludeUsers: APPLIED' }
        }


        #IncludeUsers
        if ($Policy.Conditions.Users.IncludeUsers -eq 'All') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeUsers: APPLIED' }
            $UserMatch = $true
        } elseif ($Policy.Conditions.Users.includeGuestsOrExternalUsers.GuestOrExternalUserTypes -and $ConditionsToSimulate.UserId -eq 'GuestsOrExternalUsers') {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeUsers: APPLIED' }
            $UserMatch = $true
        } elseif ($Policy.Conditions.Users.IncludeUsers -contains $ConditionsToSimulate.UserId) {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeUsers: APPLIED' }
            $UserMatch = $true
        } else {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message 'IncludeUsers: NOT APPLIED' }
            $UserMatch = $false
        }


        if ($PolicyMatch) {
            if ($GroupMatch -or $UserMatch) {
                if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message "POLICY APPLIED: TRUE" }
                $CustomObject | Add-Member -MemberType NoteProperty -Name "Match" -Value $true
            } else {
                if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message "POLICY APPLIED: FALSE" }
                $CustomObject | Add-Member -MemberType NoteProperty -Name "Match" -Value $false
            }
        } else {
            if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message "POLICY APPLIED: FALSE" }
            $CustomObject | Add-Member -MemberType NoteProperty -Name "Match" -Value $false
        }


        $CustomObject

        if ($VerbosePolicyEvaluation) { Write-Verbose -Verbose -Message '' }
    }


    Write-Verbose -Verbose -Message "Results..."


    if ($IncludeNonMatchingPolicies) {
        $Result
    } else {
        $Result | where Match -eq $true
    }


    if ($SummarizedOutput) {
        $Enforcement = @((($Result | where Match -eq $True).GrantControls | ConvertFrom-Json -ErrorAction SilentlyContinue).BuiltInControls | Select-Object -Unique)

        if ((($Result | where Match -eq $True).GrantControls | ConvertFrom-Json -ErrorAction SilentlyContinue).AuthenticationStrength -eq $true) {
            $Enforcement += 'authenticationStrength'
        }

        if ((($Result | where Match -eq $True).GrantControls | ConvertFrom-Json -ErrorAction SilentlyContinue).TermsOfUse | Select-Object -Unique) {
            $Enforcement += 'termsOfUse'
        }

        $CustomControls = ((($Result | where Match -eq $True).GrantControls | ConvertFrom-Json -ErrorAction SilentlyContinue).CustomAuthenticationFactors | Select-Object -Unique)

        if ($CustomControls) {
            $Enforcement += $CustomControls
        }

        if ($Enforcement -contains 'block') {
            $Enforcement = 'block'
        }

        Write-Host ''
        Write-Host -ForegroundColor Cyan 'Entra ID Sign-In test parameters:'
        Write-Host -ForegroundColor Magenta ($ConditionsToSimulate | Format-List | Out-String)

        Write-Host -ForegroundColor Cyan 'Applied Conditional Access policies:'

        $AppliedPolicies = foreach ($Policy in ($Result | where Match -eq $True)) {
            $EnforcementPerPolicy = @(($Policy.GrantControls | ConvertFrom-Json -ErrorAction SilentlyContinue).BuiltInControls | Select-Object -Unique)

            if (($Policy.GrantControls | ConvertFrom-Json -ErrorAction SilentlyContinue).AuthenticationStrength -eq $true) {
                $EnforcementPerPolicy += 'authenticationStrength'
            }

            if (($Policy.GrantControls | ConvertFrom-Json -ErrorAction SilentlyContinue).TermsOfUse | Select-Object -Unique) {
                $EnforcementPerPolicy += 'termsOfUse'
            }

            $CustomControls = (($Policy.GrantControls | ConvertFrom-Json -ErrorAction SilentlyContinue).CustomAuthenticationFactors | Select-Object -Unique)

            if ($CustomControls) {
                $EnforcementPerPolicy += $CustomControls
            }

            $CustomObject = New-Object -TypeName psobject
            $CustomObject | Add-Member -MemberType NoteProperty -Name "Policy" -Value ($Policy).Policy

            $Operator = ($Policy).GrantControls.Operator

            $CustomObject | Add-Member -MemberType NoteProperty -Name "Operator" -Value ((($Policy).GrantControls | ConvertFrom-Json).Operator)

            $CustomObject | Add-Member -MemberType NoteProperty -Name "Controls" -Value $EnforcementPerPolicy
            $CustomObject
        }

        Write-Host -ForegroundColor Magenta ($AppliedPolicies | Format-Table | Out-String)

        if (!($AppliedPolicies)) {
            Write-Host -ForegroundColor DarkGray 'None'
            Write-Host ''
            Write-Host ''
        }

        Write-Host -ForegroundColor Cyan "Enforced controls:"

        foreach ($Row in ($Enforcement -replace " ", "`n")) {
            if ($Row -eq 'block') {
                Write-Host -ForegroundColor Red $Row
            } else {
                Write-Host -ForegroundColor Green $Row
            }
        }

        if (!($Enforcement)) {
            Write-Host ''
            Write-Host -ForegroundColor DarkGray 'No controls enforced :('
            Write-Host ''
        }

        Write-Host ''
    }


    Write-Verbose -Verbose -Message "Done!"
}