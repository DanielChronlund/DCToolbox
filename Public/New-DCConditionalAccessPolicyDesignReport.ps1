function New-DCConditionalAccessPolicyDesignReport {
    <#
        .SYNOPSIS
            Automatically generate an Excel report containing your current Conditional Access policy design.

        .DESCRIPTION
            Uses Microsoft Graph to fetch all Conditional Access policies and exports an Excel report, You can use the report as documentation, design document, or to get a nice overview of all your policies.

            The CMDlet also uses the PowerShell Excel Module for the export to Excel. You can install this module with:
            Install-Module ImportExcel -Force

            The report is exported to Excel and will automatically open. In Excel, please do this:
            1. Select all cells.
            2. Click on "Wrap Text".
            3. Click on "Top Align".

            The report is now easier to read.

            The user running this CMDlet (the one who signs in when the authentication pops up) must have the appropriate permissions in Entra ID (Global Admin, Security Admin, Conditional Access Admin, etc).

        .INPUTS
            None

        .OUTPUTS
            Excel report with all Conditional Access policies.

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            New-DCConditionalAccessPolicyDesignReport
    #>



    # ----- [Initialisations] -----

    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Check PowerShell version.
    Confirm-DCPowerShellVersion -Verbose


    # Check if the Excel module is installed.
    if (Get-Module -ListAvailable -Name "ImportExcel") {
        # Do nothing.
    } else {
        Write-Error -Exception "The Excel PowerShell module is not installed. Please, run 'Install-Module ImportExcel -Force' as an admin and try again." -ErrorAction Stop
    }


    # Check Microsoft Graph PowerShell module.
    Install-DCMicrosoftGraphPowerShellModule -Verbose


    # Connect to Microsoft Graph.
    Connect-DCMsGraphAsUser -Scopes 'Policy.Read.ConditionalAccess', 'Application.Read.All', 'Policy.Read.All', 'Directory.Read.All' -Verbose


    # Export all Conditional Access policies from Microsoft Graph as JSON.
    Write-Verbose -Verbose -Message "Generating Conditional Access policy design report..."

    # Fetch conditional access policies.
    Write-Verbose -Verbose -Message "Getting all Conditional Access policies..."
    $CAPolicies = Get-MgIdentityConditionalAccessPolicy

    # Fetch service principals for id translation.
    $EnterpriseApps = Get-MgServicePrincipal

    # Fetch roles for id translation.
    $EntraIDRoles =  Get-MgDirectoryRoleTemplate | Select-Object DisplayName, Description, Id | Sort-Object DisplayName


    # Format the result.
    $Result = foreach ($Policy in $CAPolicies) {
        $CustomObject = New-Object -TypeName psobject


        # displayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "displayName" -Value (Out-String -InputObject $Policy.displayName)


        # state
        $CustomObject | Add-Member -MemberType NoteProperty -Name "state" -Value (Out-String -InputObject $Policy.state)


        # includeUsers
        $Users = foreach ($User in $Policy.conditions.users.includeUsers) {
            if ($User -ne 'All' -and $User -ne 'GuestsOrExternalUsers' -and $User -ne 'None') {
                (Get-MgUser -Filter "id eq '$User'").userPrincipalName
            }
            else {
                $User
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeUsers" -Value (Out-String -InputObject $Users)


        # excludeUsers
        $Users = foreach ($User in $Policy.conditions.users.excludeUsers) {
            if ($User -ne 'All' -and $User -ne 'GuestsOrExternalUsers' -and $User -ne 'None') {
                (Get-MgUser -Filter "id eq '$User'").userPrincipalName
            }
            else {
                $User
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeUsers" -Value (Out-String -InputObject $Users)


        # includeGroups
        $Groups = foreach ($Group in $Policy.conditions.users.includeGroups) {
            if ($Group -ne 'All' -and $Group -ne 'None') {
                (Get-MgGroup -Filter "id eq '$Group'").DisplayName
            }
            else {
                $Group
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeGroups" -Value (Out-String -InputObject $Groups)


        # excludeGroups
        $Groups = foreach ($Group in $Policy.conditions.users.excludeGroups) {
            if ($Group -ne 'All' -and $Group -ne 'None') {
                (Get-MgGroup -Filter "id eq '$Group'").DisplayName
            }
            else {
                $Group
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeGroups" -Value (Out-String -InputObject $Groups)


        # includeRoles
        $Roles = foreach ($Role in $Policy.conditions.users.includeRoles) {
            if ($Role -ne 'None' -and $Role -ne 'All') {
                $RoleToCheck = ($EntraIDRoles | Where-Object { $_.Id -eq $Role }).displayName

                if ($RoleToCheck) {
                    $RoleToCheck
                }
                else {
                    $Role
                }
            }
            else {
                $Role
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeRoles" -Value (Out-String -InputObject $Roles)


        # excludeRoles
        $Roles = foreach ($Role in $Policy.conditions.users.excludeRoles) {
            if ($Role -ne 'None' -and $Role -ne 'All') {
                $RoleToCheck = ($EntraIDRoles | Where-Object { $_.Id -eq $Role }).displayName

                if ($RoleToCheck) {
                    $RoleToCheck
                }
                else {
                    $Role
                }
            }
            else {
                $Role
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeRoles" -Value (Out-String -InputObject $Roles)


        # includeApplications
        $Applications = foreach ($Application in $Policy.conditions.applications.includeApplications) {
            if ($Application -ne 'None' -and $Application -ne 'All' -and $Application -ne 'Office365') {
                ($EnterpriseApps | Where-Object { $_.AppId -eq $Application }).displayName
            }
            else {
                $Application
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeApplications" -Value (Out-String -InputObject $Applications)


        # excludeApplications
        $Applications = foreach ($Application in $Policy.conditions.applications.excludeApplications) {
            if ($Application -ne 'None' -and $Application -ne 'All' -and $Application -ne 'Office365') {
                ($EnterpriseApps | Where-Object { $_.AppId -eq $Application }).displayName
            }
            else {
                $Application
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeApplications" -Value (Out-String -InputObject $Applications)


        # includeUserActions
        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeUserActions" -Value (Out-String -InputObject $Policy.conditions.applications.includeUserActions)


        # userRiskLevels
        $CustomObject | Add-Member -MemberType NoteProperty -Name "userRiskLevels" -Value (Out-String -InputObject $Policy.conditions.userRiskLevels)


        # signInRiskLevels
        $CustomObject | Add-Member -MemberType NoteProperty -Name "signInRiskLevels" -Value (Out-String -InputObject $Policy.conditions.signInRiskLevels)


        # includePlatforms
        $CustomObject | Add-Member -MemberType NoteProperty -Name "includePlatforms" -Value (Out-String -InputObject $Policy.conditions.platforms.includePlatforms)


        # excludePlatforms
        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludePlatforms" -Value (Out-String -InputObject $Policy.conditions.platforms.excludePlatforms)


        # clientAppTypes
        $CustomObject | Add-Member -MemberType NoteProperty -Name "clientAppTypes" -Value (Out-String -InputObject $Policy.conditions.clientAppTypes)


        # includeLocations
        $includeLocations = foreach ($includeLocation in $Policy.conditions.locations.includeLocations) {
            if ($includeLocation -ne 'All' -and $includeLocation -ne 'AllTrusted' -and $includeLocation -ne '00000000-0000-0000-0000-000000000000') {
                (Get-MgIdentityConditionalAccessNamedLocation -Filter "Id eq '$includeLocation'").DisplayName
            }
            elseif ($includeLocation -eq '00000000-0000-0000-0000-000000000000') {
                'MFA Trusted IPs'
            }
            else {
                $includeLocation
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeLocations" -Value (Out-String -InputObject $includeLocations)


        # excludeLocation
        $excludeLocations = foreach ($excludeLocation in $Policy.conditions.locations.excludeLocations) {
            if ($excludeLocation -ne 'All' -and $excludeLocation -ne 'AllTrusted' -and $excludeLocation -ne '00000000-0000-0000-0000-000000000000') {
                (Get-MgIdentityConditionalAccessNamedLocation -Filter "Id eq '$includeLocation'").DisplayName
            }
            elseif ($excludeLocation -eq '00000000-0000-0000-0000-000000000000') {
                'MFA Trusted IPs'
            }
            else {
                $excludeLocation
            }
        }


        # excludeLocations
        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeLocations" -Value (Out-String -InputObject $excludeLocations)


        # grantControls
        $CustomObject | Add-Member -MemberType NoteProperty -Name "grantControls" -Value (Out-String -InputObject $Policy.grantControls.builtInControls)


        # termsOfUse
        $TermsOfUses = foreach ($TermsOfUse in $Policy.grantControls.termsOfUse) {
            $GraphUri = "https://graph.microsoft.com/v1.0/agreements/$TermsOfUse"
            (Get-MgAgreement | where Id -eq $TermsOfUse).displayName
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "termsOfUse" -Value (Out-String -InputObject $TermsOfUses)


        # operator
        $CustomObject | Add-Member -MemberType NoteProperty -Name "operator" -Value (Out-String -InputObject $Policy.grantControls.operator)


        # sessionControlsapplicationEnforcedRestrictions
        $CustomObject | Add-Member -MemberType NoteProperty -Name "sessionControlsapplicationEnforcedRestrictions" -Value (Out-String -InputObject $Policy.sessionControls.applicationEnforcedRestrictions.isEnabled)


        # sessionControlscloudAppSecurity
        $CustomObject | Add-Member -MemberType NoteProperty -Name "sessionControlscloudAppSecurity" -Value (Out-String -InputObject $Policy.sessionControls.cloudAppSecurity.isEnabled)


        # sessionControlssignInFrequency
        $CustomObject | Add-Member -MemberType NoteProperty -Name "sessionControlssignInFrequency" -Value (Out-String -InputObject $Policy.sessionControls.signInFrequency)


        # sessionControlspersistentBrowser
        $CustomObject | Add-Member -MemberType NoteProperty -Name "sessionControlspersistentBrowser" -Value (Out-String -InputObject $Policy.sessionControls.persistentBrowser)


        # Return object.
        $CustomObject
    }


    # Export the result to Excel.
    Write-Verbose -Verbose -Message "Exporting report to Excel..."
    $Path = "$((Get-Location).Path)\Conditional Access Policy Design Report $(Get-Date -Format 'yyyy-MM-dd').xlsx"
    $Result | Export-Excel -Path $Path -WorksheetName "CA Policies" -BoldTopRow -FreezeTopRow -AutoFilter -AutoSize -ClearSheet -Show


    Write-Verbose -Verbose -Message "Saved $Path"
    Write-Verbose -Verbose -Message "Done!"
}