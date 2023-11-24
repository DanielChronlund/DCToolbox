function New-DCEntraIDAppPermissionsReport {
    <#
        .SYNOPSIS
            Generate a report containing all Entra ID Enterprise Apps and App Registrations with API permissions (application permissions only) in the tenant.

        .DESCRIPTION
            Uses Microsoft Graph to fetch all Entra ID Enterprise Apps and App Registrations with API permissions (application permissions only) and generate a report. The report includes app names, API permissions, secrets/certificates, and app owners.

            The purpose is to find vulnerable applications and API permissions in Entra ID.

            Applications marked with 'AppHostedInExternalTenant = False' also has a corresponding App Registration in this tenant. This means that App Registration Owners has the same permissions as the application.

        .INPUTS
            None

        .OUTPUTS
            Entra ID apps with API permissions.

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            # Get all API application permissions assigned to applications in tenant.
            New-DCEntraIDAppPermissionsReport

        .EXAMPLE
            # Look for sensitive permissions.
            $Result = New-DCEntraIDAppPermissionsReport
            $Result | where RoleName -in 'RoleManagement.ReadWrite.Directory', 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All'

        .EXAMPLE
            # Export report to Excel for further filtering and analysis.
            $Result = New-DCEntraIDAppPermissionsReport
            $Path = "$((Get-Location).Path)\Entra ID Enterprise Apps Report $(Get-Date -Format 'yyyy-MM-dd').xlsx"
            $Result | Export-Excel -Path $Path -WorksheetName "Enterprise Apps" -BoldTopRow -FreezeTopRow -AutoFilter -AutoSize -ClearSheet -Show
    #>



    # ----- [Initializations] -----

    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Check PowerShell version.
    Confirm-DCPowerShellVersion -Verbose


    # Check Microsoft Graph PowerShell module.
    Install-DCMicrosoftGraphPowerShellModule -Verbose


    # Connect to Microsoft Graph.
    Connect-DCMsGraphAsUser -Scopes 'Application.Read.All', 'Directory.Read.All' -Verbose


    # Service Principals (shadow apps representing apps in any tenant, this or 3rd party).
    Write-Verbose -Verbose -Message "Fetching service principals..."
    $ServicePrincipals = Get-MgServicePrincipal -All | ConvertTo-Json -Depth 10 | ConvertFrom-Json

    # Applications (apps registered and hosted in this tenant, used in this tenant or shared with others).
    Write-Verbose -Verbose -Message "Fetching app registrations..."
    $Applications = Get-MgApplication -All | ConvertTo-Json -Depth 10 | ConvertFrom-Json

    # App roles.
    Write-Verbose -Verbose -Message "Fetching API permissions..."
    $AppRoles = Find-MgGraphPermission -All


    # Application permissions.
    Write-Verbose -Verbose -Message "Going through $($ServicePrincipals.Count) applications..."
    $APIPermissions = foreach ($ServicePrincipal in $ServicePrincipals) {
        $Permissions = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ServicePrincipal.Id)/appRoleAssignments" | ConvertTo-Json -Depth 10 | ConvertFrom-Json).value

        $Id = ($Applications | where appId -eq $ServicePrincipal.appId).id
        $Owners = $null

        if ($Id) {
            $Owners = ((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/$Id/owners" | ConvertTo-Json -Depth 10 | ConvertFrom-Json).value).userPrincipalName | Format-List | Out-String
        }

        $publisherDomain = ($Applications | where appId -eq $ServicePrincipal.appId).publisherDomain

        $AppCertificates = ($Applications | where appId -eq $ServicePrincipal.appId).keyCredentials | Format-Table -Property displayName, startDateTime, endDateTime | Out-String

        $AppSecrets = ($Applications | where appId -eq $ServicePrincipal.appId).passwordCredentials | Format-Table -Property displayName, startDateTime, endDateTime | Out-String

        foreach ($Permission in $Permissions) {
            $AppRole = $AppRoles | where Id -eq $Permission.appRoleId

            $CustomObject = New-Object -TypeName psobject
            $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value $Permission.principalDisplayName
            $CustomObject | Add-Member -MemberType NoteProperty -Name "ClientID" -Value $ServicePrincipal.appId
            $CustomObject | Add-Member -MemberType NoteProperty -Name "Owners" -Value $Owners
            $CustomObject | Add-Member -MemberType NoteProperty -Name "SignInAudience" -Value $ServicePrincipal.signInAudience
            $CustomObject | Add-Member -MemberType NoteProperty -Name "AppHostedInExternalTenant" -Value ($publisherDomain -eq $null)
            $CustomObject | Add-Member -MemberType NoteProperty -Name "AppCertificates" -Value $AppCertificates
            $CustomObject | Add-Member -MemberType NoteProperty -Name "AppSecrets" -Value $AppSecrets
            $CustomObject | Add-Member -MemberType NoteProperty -Name "API" -Value $Permission.resourceDisplayName
            $CustomObject | Add-Member -MemberType NoteProperty -Name "RoleId" -Value $Permission.appRoleId
            $CustomObject | Add-Member -MemberType NoteProperty -Name "RoleName" -Value $AppRole.Name
            $CustomObject | Add-Member -MemberType NoteProperty -Name "RoleAdded" -Value $Permission.createdDateTime
            $CustomObject | Add-Member -MemberType NoteProperty -Name "RoleDescription" -Value $AppRole.Description
            $CustomObject
        }
    }

    $APIPermissions


    Write-Verbose -Verbose -Message "Done!"
}
