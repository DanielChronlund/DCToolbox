function Copy-DCExample {
    function CreateMenu {
        param
        (
            [parameter(Mandatory = $true)]
            [string]$MenuTitle,
            [parameter(Mandatory = $true)]
            [string[]]$MenuChoices
        )

        # Create a counter.
        $Counter = 1

        # Write menu title.
        Write-Host -ForegroundColor "Yellow" "*** $MenuTitle ***"
        Write-Host -ForegroundColor "Yellow" ""

        # Generate the menu choices.
        foreach ($MenuChoice in $MenuChoices) {
            Write-Host -ForegroundColor "Yellow" "[$Counter] $MenuChoice"

            # Add to counter.
            $Counter = $Counter + 1
        }

        # Write empty line.
        Write-Host -ForegroundColor "Yellow" ""

        # Write exit line.
        Write-Host -ForegroundColor "Yellow" "[0] Quit"

        # Write empty line.
        Write-Host -ForegroundColor "Yellow" ""

        # Prompt user for input.
        $prompt = "Choice"
        Read-Host $prompt

        # Return users choice.
        return $prompt
    }


    # Function for handling the menu choice.
    function HandleMenuChoice {
        param
        (
            [parameter(Mandatory = $true)]
            [string[]]$MenuChoice
        )

        # Menu choices.
        switch ($MenuChoice) {
            1 {
                $Snippet = @'
# Microsoft Graph with PowerShell examples.


# *** Connect Examples ***

# Connect to Microsoft Graph with delegated permissions.
$AccessToken = Invoke-DCEntraIDDeviceAuthFlow -ReturnAccessTokenInsteadOfRefreshToken


# Connect to Microsoft Graph with application permissions.
$Parameters = @{
    TenantName = 'example.onmicrosoft.com'
    ClientID = ''
    ClientSecret = ''
}

$AccessToken = Connect-DCMsGraphAsApplication @Parameters


# *** Microsoft Graph Query Examples ***

# GET data from Microsoft Graph.
$Parameters = @{
    AccessToken = $AccessToken
    GraphMethod = 'GET'
    GraphUri = 'https://graph.microsoft.com/v1.0/users'
}

Invoke-DCMsGraphQuery @Parameters


# POST changes to Microsoft Graph.
$Parameters = @{
    AccessToken = $AccessToken
    GraphMethod = 'POST'
    GraphUri = 'https://graph.microsoft.com/v1.0/users'
    GraphBody = @"
<Insert JSON request body here>
"@
}

Invoke-DCMsGraphQuery @Parameters


# PUT changes to Microsoft Graph.
$Parameters = @{
    AccessToken = $AccessToken
    GraphMethod = 'PUT'
    GraphUri = 'https://graph.microsoft.com/v1.0/users'
    GraphBody = @"
<Insert JSON request body here>
"@
}

Invoke-DCMsGraphQuery @Parameters


# PATCH changes to Microsoft Graph.
$Parameters = @{
    AccessToken = $AccessToken
    GraphMethod = 'PATCH'
    GraphUri = 'https://graph.microsoft.com/v1.0/users'
    GraphBody = @"
<Insert JSON request body here>
"@
}

Invoke-DCMsGraphQuery @Parameters


# DELETE data from Microsoft Graph.
$Parameters = @{
    AccessToken = $AccessToken
    GraphMethod = 'DELETE'
    GraphUri = 'https://graph.microsoft.com/v1.0/users'
}

Invoke-DCMsGraphQuery @Parameters


<#
    Filter examples:
    /users?$filter=startswith(givenName,'J')
    /users?$filter=givenName eq 'Test'
#>


# Learn more about the Graph commands.
help Connect-DCMsGraphAsDelegated -Full
help Connect-DCMsGraphAsApplication -Full
help Invoke-DCMsGraphQuery -Full

'@

                Set-Clipboard $Snippet

                Write-Host -ForegroundColor "Yellow" ""
                Write-Host -ForegroundColor "Yellow" "Example copied to clipboard!"
                Write-Host -ForegroundColor "Yellow" ""
            }
            2 {
                $Snippet = @'
# Manage Conditional Access as code.

<#
The user running this (the one who signs in when the authentication pops up) must have the appropriate permissions in Entra ID (Global Admin, Security Admin, Conditional Access Admin, etc).
#>

# OPTIONAL: To get another Global Admin to pre-consent to ALL required permissions for ALL Conditional Access tools in DCToolbox, ask them to run the following code in PowerShell (and make sure they Consent these permissions on behalf of the whole organisation).

Install-Module Microsoft.Graph -Scope CurrentUser -Force

$Scopes = 'Group.ReadWrite.All',
'Policy.ReadWrite.ConditionalAccess',
'Policy.Read.All', 'Directory.Read.All',
'Agreement.ReadWrite.All',
'Application.Read.All',
'RoleManagement.ReadWrite.Directory'

Connect-MgGraph -Scopes $Scopes



# --- Show Conditional Access Policies ---

# Show basic info about Conditional Access policies in the tenant.
Get-DCConditionalAccessPolicies

# Show policy names only.
Get-DCConditionalAccessPolicies -NamesOnly

# Show Conditional Access policies in the tenant with targeted users and groups.
Get-DCConditionalAccessPolicies -ShowTargetResources -PrefixFilter 'GLOBAL - GRANT - MFA for All Users'

# Show detailed info about Conditional Access policies in the tenant.
Get-DCConditionalAccessPolicies -Details -PrefixFilter 'GLOBAL - GRANT - MFA for All Users'

# Show Named Locations in the tenant.
Get-DCNamedLocations

# Filter Named Locations with a prefix.
Get-DCNamedLocations -PrefixFilter 'OFFICE-'

# List all trusted IP addresses in Named Locations.
(Get-DCNamedLocations | where isTrusted -eq $true).ipRanges | Select-Object -Unique | Sort-Object

# List all countries in Named Locations.
(Get-DCNamedLocations).countriesAndRegions | Select-Object -Unique | Sort-Object


# --- Rename Conditional Access Policies ---

# Rename Conditional Access policies.
Rename-DCConditionalAccessPolicies -PrefixFilter 'PILOT - ' -AddCustomPrefix 'PROD - '

# Add a prefix to specific Conditional Access policies.
Rename-DCConditionalAccessPolicies -PrefixFilter 'GLOBAL - ' -AddCustomPrefix 'OLD - GLOBAL - '

# Add a prefix to ALL existing Conditional Access policies.
Rename-DCConditionalAccessPolicies -AddCustomPrefix 'OLD - '


# --- Delete Conditional Access Policies ---

# Delete ALL Conditional Access policies.
Remove-DCConditionalAccessPolicies

# Delete all Conditional Access policies with a specific prefix.
Remove-DCConditionalAccessPolicies -PrefixFilter 'OLD - '

# Delete all Conditional Access policies WITHOUT a specific prefix (like -PrefixFilter but reversed).
Remove-DCConditionalAccessPolicies -ReversedPrefixFilter 'GLOBAL - '


# --- Deploy Conditional Access Baseline PoC ---

# Deploy a complete Conditional Access PoC in report-only mode from https://danielchronlund.com.
Deploy-DCConditionalAccessBaselinePoC

# Deploy a complete Conditional Access PoC in production mode from https://danielchronlund.com (Dangerous).
Deploy-DCConditionalAccessBaselinePoC -SkipReportOnlyMode

# Deploy a complete Conditional Access PoC in report-only mode with a PILOT prefix.
Deploy-DCConditionalAccessBaselinePoC -AddCustomPrefix 'PILOT - '


# --- Bulk Manage Conditional Access Policies ---

# Toggle Conditional Access policies between 'All users' and specified pilot group.
Set-DCConditionalAccessPoliciesPilotMode -PrefixFilter 'GLOBAL - ' -PilotGroupName 'Conditional Access Pilot' -EnablePilot

# Toggle Conditional Access policies between specified pilot group and 'All users'.
Set-DCConditionalAccessPoliciesPilotMode -PrefixFilter 'GLOBAL - ' -PilotGroupName 'Conditional Access Pilot' -EnableProduction

# Toggle specified Conditional Access policies between 'Enabled' and 'Report-only'.
Set-DCConditionalAccessPoliciesReportOnlyMode -PrefixFilter 'GLOBAL - ' -SetToReportOnly

# Toggle specified Conditional Access policies between 'Report-only' and 'Enabled'.
Set-DCConditionalAccessPoliciesReportOnlyMode -PrefixFilter 'GLOBAL - ' -SetToEnabled

# Exclude specified break glass group from all Conditional Access policies.
Add-DCConditionalAccessPoliciesBreakGlassGroup -PrefixFilter 'GLOBAL - ' -ExcludeGroupName 'Excluded from Conditional Access'


# --- Export/Import Conditional Access Policies (JSON file) ---

# Export your Conditional Access policies to a JSON file for backup (default file name).
Export-DCConditionalAccessPolicyDesign

# Export your Conditional Access policies to a JSON file for backup (custom file name).
Export-DCConditionalAccessPolicyDesign -FilePath 'C:\Temp\Conditional Access Backup.json'

# Export Conditional Access policies with a specifc prefix.
$Parameters = @{
    FilePath = 'Conditional Access.json'
    PrefixFilter = 'GLOBAL - '
}
Export-DCConditionalAccessPolicyDesign @Parameters

# Import Conditional Access policies from a JSON file exported by Export-DCConditionalAccessPolicyDesign.
$Parameters = @{
    FilePath = 'C:\Temp\Conditional Access Backup.json'
    SkipReportOnlyMode = $false
    DeleteAllExistingPolicies = $false
}

Import-DCConditionalAccessPolicyDesign @Parameters

# Import Conditional Access policies and add a custom prefix.
$Parameters = @{
    FilePath = 'C:\Temp\Conditional Access Backup.json'
    SkipReportOnlyMode = $false
    DeleteAllExistingPolicies = $false
    AddCustomPrefix = 'TEST - '
}

Import-DCConditionalAccessPolicyDesign @Parameters


# --- Generate Conditional Access Excel Reports ---

# Export Conditional Access policy design report to Excel.
New-DCConditionalAccessPolicyDesignReport

# Export Conditional Access Assignment Report to Excel.
$Parameters = @{
    IncludeGroupMembers = $false
}

New-DCConditionalAccessAssignmentReport @Parameters


# --- Conditional Access What If Simulation ---

# Run basic evaluation with default settings.
Invoke-DCConditionalAccessSimulation | Format-List


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


# Run basic evaluation offline against a JSON of Conditional Access policies.
Invoke-DCConditionalAccessSimulation -JSONFile 'Conditional Access Backup.json' | Format-List

'@

                Set-Clipboard $Snippet

                Write-Host -ForegroundColor "Yellow" ""
                Write-Host -ForegroundColor "Yellow" "Example copied to clipboard!"
                Write-Host -ForegroundColor "Yellow" ""
            }
            3 {
                $Snippet = @'
# Install required modules (if you are local admin) (only needed first time).
Install-Module -Name DCToolbox -Force
Install-Package msal.ps -Force

# Install required modules as current user (if you're not local admin) (only needed first time).
Install-Module -Name DCToolbox -Scope CurrentUser -Force
Install-Package msal.ps -Scope CurrentUser -Force

# Enable one of your Entra ID PIM roles.
Enable-DCEntraIDPIMRole

# Enable multiple Entra ID PIM roles.
Enable-DCEntraIDPIMRole -RolesToActivate 'Exchange Administrator', 'Security Reader'

# Fully automate Entra ID PIM role activation.
Enable-DCEntraIDPIMRole -RolesToActivate 'Exchange Administrator', 'Security Reader' -UseMaximumTimeAllowed -Reason 'Performing some Exchange security coniguration according to change #12345.'

<#
    Example output:

    VERBOSE: Connecting to Entra ID...

    *** Activate PIM Role ***

    [1] User Account Administrator
    [2] Application Administrator
    [3] Security Administrator
    [0] Exit

    Choice: 3
    Reason: Need to do some security work!
    Duration [1 hour(s)]: 1
    VERBOSE: Activating PIM role...
    VERBOSE: Security Administrator has been activated until 11/13/2020 11:41:01!
#>


# Learn more about Enable-DCEntraIDPIMRole.
help Enable-DCEntraIDPIMRole -Full

# Privileged Identity Management | My roles:
# https://portal.azure.com/#blade/Microsoft_Azure_PIMCommon/ActivationMenuBlade/aadmigratedroles

# Privileged Identity Management | Entra ID roles | Overview:
# https://portal.azure.com/#blade/Microsoft_Azure_PIMCommon/ResourceMenuBlade/aadoverview/resourceId//resourceType/tenant/provider/aadroles

'@

                Set-Clipboard $Snippet

                Write-Host -ForegroundColor "Yellow" ""
                Write-Host -ForegroundColor "Yellow" "Example copied to clipboard!"
                Write-Host -ForegroundColor "Yellow" ""
            }
            4 {
                $Snippet = @'
# Learn how to set this up.
Get-Help New-DCStaleAccountReport -Full


# Export stale Entra ID account report to Excel.
$Parameters = @{
    ClientID = ''
    ClientSecret = ''
    LastSeenDaysAgo = 30
}

New-DCStaleAccountReport @Parameters


# Export stale GUEST Entra ID account report to Excel.
$Parameters = @{
    ClientID = ''
    ClientSecret = ''
    LastSeenDaysAgo = 60
    OnlyGuests = $true
}

New-DCStaleAccountReport @Parameters


# Export stale MEMBER Entra ID account report to Excel.
$Parameters = @{
    ClientID = ''
    ClientSecret = ''
    LastSeenDaysAgo = 60
    OnlyMembers = $true
}

New-DCStaleAccountReport @Parameters


# Export stale GUEST Entra ID account report with group/team membership to Excel.
$Parameters = @{
    ClientID = ''
    ClientSecret = ''
    LastSeenDaysAgo = 60
    OnlyGuests = $true
    IncludeMemberOf = $true
}

New-DCStaleAccountReport @Parameters

'@

                Set-Clipboard $Snippet

                Write-Host -ForegroundColor "Yellow" ""
                Write-Host -ForegroundColor "Yellow" "Example copied to clipboard!"
                Write-Host -ForegroundColor "Yellow" ""
            }
            5 {
                $Snippet = @'
### Clean up phone authentication methods for all Entra ID users ###

<#
    Set the registered applications ClientID and ClientSecret further down. This script requires the following Microsoft Graph permissions:
    Delegated:
        UserAuthenticationMethod.ReadWrite.All
        Reports.Read.All

    It also requires the DCToolbox PowerShell module:
    Install-Module -Name DCToolbox -Force

    Note that this script cannot delete a users phone method if it is set as the default authentication method. Microsoft Graph cannot, as of 7/10 2021, manage the default authentication method for users in Entra ID. Hopefully the users method of choice was changed when he/she switched to the Microsoft Authenticator app or another MFA/passwordless authentication method. If not, ask them to change the default method before running the script.

    Use the following report to understand how many users are registered for phone authentication (can lag up to 48 hours): https://portal.azure.com/#blade/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/AuthMethodsActivity
#>


# Connect to Microsoft Graph with delegated permissions.
Write-Verbose -Verbose -Message 'Connecting to Microsoft Graph...'
$Parameters = @{
    ClientID     = ''
    ClientSecret = ''
}

$AccessToken = Connect-DCMsGraphAsDelegated @Parameters


# Fetch all users with phone authentication enabled from the Entra ID authentication usage report (we're using this usage report to save time and resources when querying Graph, but their might be a 24 hour delay in the report data).
Write-Verbose -Verbose -Message 'Fetching all users with any phone authentication methods registered...'
$Parameters = @{
    AccessToken = $AccessToken
    GraphMethod = 'GET'
    GraphUri    = "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails?`$filter=authMethods/any(t:t eq microsoft.graph.registrationAuthMethod'mobilePhone') or authMethods/any(t:t eq microsoft.graph.registrationAuthMethod'officePhone')"
}

$AllUsersWithPhoneAuthentication = Invoke-DCMsGraphQuery @Parameters


# Output the number of users found.
Write-Verbose -Verbose -Message "Found $($AllUsersWithPhoneAuthentication.Count) users!"


# Loop through all those users.
$ProgressCounter = 0
foreach ($User in $AllUsersWithPhoneAuthentication) {
    # Show progress bar.
    $ProgressCounter += 1
    [int]$PercentComplete = ($ProgressCounter / $AllUsersWithPhoneAuthentication.Count) * 100
    Write-Progress -PercentComplete $PercentComplete -Activity "Processing user $ProgressCounter of $($AllUsersWithPhoneAuthentication.Count)" -Status "$PercentComplete% Complete"

    # Retrieve a list of registered phone authentication methods for the user. This will return up to three objects, as a user can have up to three phones usable for authentication.
    Write-Verbose -Verbose -Message "Fetching phone methods for $($User.userPrincipalName)..."
    $Parameters = @{
        AccessToken = $AccessToken
        GraphMethod = 'GET'
        GraphUri    = "https://graph.microsoft.com/beta/users/$($User.userPrincipalName)/authentication/phoneMethods"
    }

    $phoneMethods = Invoke-DCMsGraphQuery @Parameters

    <#
        The value of id corresponding to the phoneType to delete is one of the following:

        b6332ec1-7057-4abe-9331-3d72feddfe41 to delete the alternateMobile phoneType.
        e37fc753-ff3b-4958-9484-eaa9425c82bc to delete the office phoneType.
        3179e48a-750b-4051-897c-87b9720928f7 to delete the mobile phoneType.
    #>

    # Loop through all user phone methods.
    foreach ($phoneMethod in $phoneMethods) {
        # Delete the phone method.
        try {
            if ($phoneMethod.phoneType) {
                Write-Verbose -Verbose -Message "Deleting phone method '$($phoneMethod.phoneType)' for $($User.userPrincipalName)..."
                $Parameters = @{
                    AccessToken = $AccessToken
                    GraphMethod = 'DELETE'
                    GraphUri    = "https://graph.microsoft.com/beta/users/$($User.userPrincipalName)/authentication/phoneMethods/$($phoneMethod.id)"
                }

                Invoke-DCMsGraphQuery @Parameters | Out-Null
            }
        }
        catch {
            Write-Warning -Message "Could not delete phone method '$($phoneMethod.phoneType)' for $($User.userPrincipalName)! Is it the users default authentication method?"
        }
    }
}


break

# BONUS SCRIPT: LIST ALL GUEST USERS WITH SMS AS A REGISTERED AUTHENTICATION METHOD.

# First, create app registration and grant it:
#  User.Read.All
#  UserAuthenticationMethod.Read.All
#  Reports.Read.All


# Connect to Microsoft Graph with delegated permissions.
Write-Verbose -Verbose -Message 'Connecting to Microsoft Graph...'
$Parameters = @{
    ClientID = ''
    ClientSecret = ''
}

$AccessToken = Connect-DCMsGraphAsDelegated @Parameters


# Fetch user authentication methods.
Write-Verbose -Verbose -Message 'Fetching all users with any phone authentication methods registered...'
$Parameters = @{
    AccessToken = $AccessToken
    GraphMethod = 'GET'
    GraphUri    = "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails?`$filter=authMethods/any(t:t eq microsoft.graph.registrationAuthMethod'mobilePhone') or authMethods/any(t:t eq microsoft.graph.registrationAuthMethod'officePhone')"
}

$AllUsersWithPhoneAuthentication = Invoke-DCMsGraphQuery @Parameters


# Fetch all guest users.
Write-Verbose -Verbose -Message 'Fetching all guest users...'
$Parameters = @{
    AccessToken = $AccessToken
    GraphMethod = 'GET'
    GraphUri    = "https://graph.microsoft.com/beta/users?`$filter=userType eq 'Guest'"
}

$AllGuestUsers = Invoke-DCMsGraphQuery @Parameters


# Check how many users who have an authentication phone number registered.
foreach ($Guest in $AllGuestUsers) {
    if ($AllUsersWithPhoneAuthentication.userPrincipalName.Contains($Guest.UserPrincipalName)) {
        Write-Output "$($Guest.displayName) ($($Guest.mail))"
    }
}

'@

                Set-Clipboard $Snippet

                Write-Host -ForegroundColor "Yellow" ""
                Write-Host -ForegroundColor "Yellow" "Example copied to clipboard!"
                Write-Host -ForegroundColor "Yellow" ""
            }
            6 {
                $Snippet = @'
<#
    .SYNOPSIS
        A simple script template.

    .DESCRIPTION
        Write a description of what the script does and how to use it.

    .PARAMETER Parameter1
        Inputs a string into the script.

    .PARAMETER Parameter2
        Inputs an integer into the script.

    .PARAMETER Parameter3
        Sets a script switch.

    .INPUTS
        None

    .OUTPUTS
        System.String

    .NOTES
        Version:        1.0
        Author:         Daniel Chronlund
        Creation Date:  2021-01-01

    .EXAMPLE
        Script-Template -Parameter "Text" -Verbose

    .EXAMPLE
        Script-Template -Parameter "Text" -Verbose
#>



# ----- [Initialisations] -----

# Script parameters.
param (
    [parameter(Mandatory = $true)]
    [string]$Parameter1 = "Text",

    [parameter(Mandatory = $true)]
    [int32]$Parameter2 = 1,

    [parameter(Mandatory = $false)]
    [switch]$Parameter3
)


# Set Error Action - Possible choices: Stop, SilentlyContinue
$ErrorActionPreference = "Stop"



# ----- [Declarations] -----

# Variable 1 description.
$Variable1 = ""

# Variable 2 description.
$Variable2 = ""



# ----- [Functions] -----

function function1
{
    <#
        .SYNOPSIS
            A brief description of the function1 function.

        .DESCRIPTION
            A detailed description of the function1 function.

        .PARAMETER Parameter1
            A description of the Parameter1 parameter.

        .EXAMPLE
            function1 -Parameter1 'Value1'
    #>


    param (
        [parameter(Mandatory = $true)]
        [string]$Parameter1
    )


    $Output = $Parameter1

    $Output
}



# ----- [Execution] -----

# Do the following.
function1 -Parameter1 'Test'



# ----- [End] -----

'@

                Set-Clipboard $Snippet

                Write-Host -ForegroundColor "Yellow" ""
                Write-Host -ForegroundColor "Yellow" "Example copied to clipboard!"
                Write-Host -ForegroundColor "Yellow" ""
            }
            7 {
                $Snippet = @'
# README: This script is an example of what you might want to/need to do if your Entra ID has been breached. This script was created in the spirit of the zero trust assume breach methodology. The idea is that if you detect that attackers are already on the inside, then you must try to kick them out. This requires multiple steps and you also must handle other resources like your on-prem AD. However, this script example helps you in the right direction when it comes to Entra ID admin roles.

# More info on my blog: https://danielchronlund.com/2021/03/29/my-azure-ad-has-been-breached-what-now/

break



# *** Connect to Entra ID ***
Import-Module AzureAdPreview
Connect-AzureAd



# *** Interesting Entra ID roles to inspect ***
$InterestingDirectoryRoles = 'Global Administrator',
'Global Reader',
'Privileged Role Administrator',
'Security Administrator',
'Application Administrator',
'Compliance Administrator'



# *** Inspect current Entra ID admins (if you use Entra ID PIM) ***

# Fetch tenant ID.
$TenantID = (Get-AzureAdTenantDetail).ObjectId

# Fetch all Entra ID role definitions.
$EntraIDRoleDefinitions = Get-AzureAdMSPrivilegedRoleDefinition -ProviderId "aadRoles" -ResourceId $TenantID | Where-Object { $_.DisplayName -in $InterestingDirectoryRoles }

# Fetch all Entra ID PIM role assignments.
$EntraIDDirectoryRoleAssignments = Get-AzureAdMSPrivilegedRoleAssignment -ProviderId "aadRoles" -ResourceId $TenantID | Where-Object { $_.RoleDefinitionId -in $EntraIDRoleDefinitions.Id }

# Fetch Entra ID role members for each role and format as custom object.
$EntraIDDirectoryRoleMembers = foreach ($EntraIDDirectoryRoleAssignment in $EntraIDDirectoryRoleAssignments) {
    $UserAccountDetails = Get-AzureAdUser -ObjectId $EntraIDDirectoryRoleAssignment.SubjectId

    $LastLogon = (Get-AzureAdAuditSigninLogs -top 1 -filter "UserId eq '$($EntraIDDirectoryRoleAssignment.SubjectId)'" | Select-Object CreatedDateTime).CreatedDateTime

    if ($LastLogon) {
        $LastLogon = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date -Date $LastLogon), (Get-TimeZone).Id)
    }

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "EntraIDDirectoryRole" -Value ($EntraIDRoleDefinitions | Where-Object { $_.Id -eq $EntraIDDirectoryRoleAssignment.RoleDefinitionId }).DisplayName
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserID" -Value $UserAccountDetails.ObjectID
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserAccount" -Value $UserAccountDetails.DisplayName
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $UserAccountDetails.UserPrincipalName
    $CustomObject | Add-Member -MemberType NoteProperty -Name "AssignmentState" -Value $EntraIDDirectoryRoleAssignment.AssignmentState
    $CustomObject | Add-Member -MemberType NoteProperty -Name "AccountCreated" -Value $UserAccountDetails.ExtensionProperty.createdDateTime
    $CustomObject | Add-Member -MemberType NoteProperty -Name "LastLogon" -Value $LastLogon
    $CustomObject
}

# List all Entra ID role members (newest first).
$EntraIDDirectoryRoleMembers | Sort-Object AccountCreated -Descending | Format-Table



# *** Inspect current Entra ID admins (only if you do NOT use Entra ID PIM) ***

# Interesting Entra ID roles to inspect.
$InterestingDirectoryRoles = 'Global Administrator',
'Global Reader',
'Privileged Role Administrator',
'Security Administrator',
'Application Administrator',
'Compliance Administrator'

# Fetch Entra ID role details.
$EntraIDDirectoryRoles = Get-AzureAdDirectoryRole | Where-Object { $_.DisplayName -in $InterestingDirectoryRoles }

# Fetch Entra ID role members for each role and format as custom object.
$EntraIDDirectoryRoleMembers = foreach ($EntraIDDirectoryRole in $EntraIDDirectoryRoles) {
    $RoleAssignments = Get-AzureAdDirectoryRoleMember -ObjectId $EntraIDDirectoryRole.ObjectId

    foreach ($RoleAssignment in $RoleAssignments) {
        $LastLogon = (Get-AzureAdAuditSigninLogs -top 1 -filter "UserId eq '$($RoleAssignment.ObjectId)'" | Select-Object CreatedDateTime).CreatedDateTime

        if ($LastLogon) {
            $LastLogon = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date -Date $LastLogon), (Get-TimeZone).Id)
        }

        $CustomObject = New-Object -TypeName psobject
        $CustomObject | Add-Member -MemberType NoteProperty -Name "EntraIDDirectoryRole" -Value $EntraIDDirectoryRole.DisplayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "UserID" -Value $RoleAssignment.ObjectID
        $CustomObject | Add-Member -MemberType NoteProperty -Name "UserAccount" -Value $RoleAssignment.DisplayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $RoleAssignment.UserPrincipalName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "AccountCreated" -Value $RoleAssignment.ExtensionProperty.createdDateTime
        $CustomObject | Add-Member -MemberType NoteProperty -Name "LastLogon" -Value $LastLogon
        $CustomObject
    }
}

# List all Entra ID role members (newest first).
$EntraIDDirectoryRoleMembers | Sort-Object AccountCreated -Descending | Format-Table



# *** Check if admin accounts are synced from on-prem (bad security) ***

# Loop through the admins from previous output and fetch sync status.
$SyncedAdmins = foreach ($EntraIDDirectoryRoleMember in $EntraIDDirectoryRoleMembers) {
    $IsSynced = (Get-AzureAdUser -ObjectId $EntraIDDirectoryRoleMember.UserID | Where-Object {$_.DirSyncEnabled -eq $true}).DirSyncEnabled

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserID" -Value $EntraIDDirectoryRoleMember.UserID
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserAccount" -Value $EntraIDDirectoryRoleMember.UserAccount
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $EntraIDDirectoryRoleMember.UserPrincipalName

    if ($IsSynced) {
        $CustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremAccount" -Value 'True'
    } else {
        $CustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremAccount" -Value 'False'
    }

    $CustomObject
}

# List admins (synced on-prem accounts first).
$SyncedAdmins | Sort-Object UserPrincipalName -Descending -Unique | Sort-Object SyncedOnPremAccount -Descending | Format-Table



# *** ON-PREM SYNC PANIC BUTTON: Block all Entra ID admin accounts that are synced from on-prem ***
# WARNING: Make sure you understand what you're doing before running this script!

# Loop through admins synced from on-prem and block sign-ins.
foreach ($SyncedAdmin in ($SyncedAdmins | Where-Object { $_.SyncedOnPremAccount -eq 'True' })) {
    Set-AzureAdUser -ObjectID $SyncedAdmin.UserID -AccountEnabled $false
}

# Check account status.
foreach ($SyncedAdmin in ($SyncedAdmins | Where-Object { $_.SyncedOnPremAccount -eq 'True' })) {
    Get-AzureAdUser -ObjectID $SyncedAdmin.UserID | Select-Object userPrincipalName, AccountEnabled
}



# *** Check admins last password set time ***

# Connect to Microsoft online services.
Connect-MsolService

# Loop through the admins from previous output and fetch LastPasswordChangeTimeStamp.
$AdminPasswordChanges = foreach ($EntraIDDirectoryRoleMember in ($EntraIDDirectoryRoleMembers| Sort-Object UserID -Unique)) {
    $LastPasswordChangeTimeStamp = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date -Date (Get-MsolUser -ObjectId $EntraIDDirectoryRoleMember.UserID | Select-Object LastPasswordChangeTimeStamp).LastPasswordChangeTimeStamp), (Get-TimeZone).Id)

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserID" -Value $EntraIDDirectoryRoleMember.UserID
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserAccount" -Value $EntraIDDirectoryRoleMember.UserAccount
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $EntraIDDirectoryRoleMember.UserPrincipalName
    $CustomObject | Add-Member -MemberType NoteProperty -Name "LastPasswordChangeTimeStamp" -Value $LastPasswordChangeTimeStamp
    $CustomObject
}

# List admins (newest passwords first).
$AdminPasswordChanges | Sort-Object LastPasswordChangeTimeStamp -Descending | Format-Table



# *** ADMIN PASSWORD PANIC BUTTON: Reset passwords for all Entra ID admins (except for current user and break glass accounts) ***
# WARNING: Make sure you understand what you're doing before running this script!

# IMPORTANT: Define your break glass accounts.
$BreakGlassAccounts = 'breakglass1@example.onmicrosoft.com', 'breakglass2@example.onmicrosoft.com'

# The current user running PowerShell against Entra ID.
$CurrentUser = (Get-AzureAdCurrentSessionInfo).Account.Id

# Loop through admins and set new complex passwords (using generated GUIDs).
foreach ($EntraIDDirectoryRoleMember in ($EntraIDDirectoryRoleMembers | Sort-Object UserPrincipalName -Unique)) {
    if ($EntraIDDirectoryRoleMember.UserPrincipalName -notin $BreakGlassAccounts -and $EntraIDDirectoryRoleMember.UserPrincipalName -ne $CurrentUser) {
        Write-Verbose -Verbose -Message "Setting new password for $($EntraIDDirectoryRoleMember.UserPrincipalName)..."
        Set-AzureAdUserPassword -ObjectId $EntraIDDirectoryRoleMember.UserID -Password (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)
    } else {
        Write-Verbose -Verbose -Message "Skipping $($EntraIDDirectoryRoleMember.UserPrincipalName)!"
    }
}

'@

                Set-Clipboard $Snippet

                Write-Host -ForegroundColor "Yellow" ""
                Write-Host -ForegroundColor "Yellow" "Example copied to clipboard!"
                Write-Host -ForegroundColor "Yellow" ""
            }
            8 {
                $Snippet = @'
# This script uses an Entra ID app registration to download all files from all M365 groups (Teams) document libraries in a tenant.

# One of the following Graph API app permissions is required:
# - Files.Read.All
# - Files.ReadWrite.All
# - Sites.Read.All
# - Sites.ReadWrite.All

# Simulate data exfiltration.
Invoke-DCM365DataExfiltration -ClientID '' -ClientSecret '' -TenantName 'COMPANY.onmicrosoft.com' -WhatIf

# Perform data exfiltration.
Invoke-DCM365DataExfiltration -ClientID '' -ClientSecret '' -TenantName 'COMPANY.onmicrosoft.com'


# This script uses an Entra ID app registration to wipe all files from all M365 groups (Teams) document libraries in a tenant.

# One of the following Graph API app permissions is required:
# - Files.ReadWrite.All
# - Sites.ReadWrite.All

# Simulate data deletion.
Invoke-DCM365DataWiper -ClientID '' -ClientSecret '' -TenantName 'COMPANY.onmicrosoft.com' -WhatIf

# Perform data deletion.
Invoke-DCM365DataWiper -ClientID '' -ClientSecret '' -TenantName 'COMPANY.onmicrosoft.com'

'@

                Set-Clipboard $Snippet

                Write-Host -ForegroundColor "Yellow" ""
                Write-Host -ForegroundColor "Yellow" "Example copied to clipboard!"
                Write-Host -ForegroundColor "Yellow" ""
            }
            100 {
                $Snippet = @'
#
'@

                Set-Clipboard $Snippet

                Write-Host -ForegroundColor "Yellow" ""
                Write-Host -ForegroundColor "Yellow" "Example copied to clipboard!"
                Write-Host -ForegroundColor "Yellow" ""
            }
            0 {
                break
            } default {
                break
            }
        }
    }


    # Create example menu.
    $Choice = CreateMenu -MenuTitle "Copy DCToolbox example to clipboard" -MenuChoices "Microsoft Graph with PowerShell examples", "Manage Conditional Access as code", "Activate an Entra ID Privileged Identity Management (PIM) role", "Manage stale Entra ID accounts", "Azure MFA SMS and voice call methods cleanup script", "General PowerShell script template", "Entra ID Security Breach Kick-Out Process", "Microsoft 365 Data Exfiltration / Wiper Attack"


    # Handle menu choice.
    HandleMenuChoice -MenuChoice $Choice
}