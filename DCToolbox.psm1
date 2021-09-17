function Get-DCHelp {
    $HelpText = @'

    ____  ____________            ____              
   / __ \/ ____/_  __/___  ____  / / /_  ____  _  __
  / / / / /     / / / __ \/ __ \/ / __ \/ __ \| |/_/
 / /_/ / /___  / / / /_/ / /_/ / / /_/ / /_/ />  <  
/_____/\____/ /_/  \____/\____/_/_.___/\____/_/|_|  

A PowerShell toolbox for Microsoft 365 security fans.

---------------------------------------------------

Author: Daniel Chronlund
Version: 1.0.21

This PowerShell module contains a collection of tools for Microsoft 365 security tasks, Microsoft Graph functions, Azure AD management, Conditional Access, zero trust strategies, attack and defense scenarios, etc.

The home of this module: https://github.com/DanielChronlund/DCToolbox

Please follow me on my blog https://danielchronlund.com, on LinkedIn and on Twitter!

@DanielChronlund


To get started, explore and copy script examples to your clipboard with:

'@

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

# Connect to Microsoft Graph with delegated credentials.
$Parameters = @{
    ClientID = ''
    ClientSecret = ''
}

$AccessToken = Connect-DCMsGraphAsDelegated @Parameters


# Connect to Microsoft Graph with application credentials.
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
You first need to register a new application in your Azure AD according to this article:
https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/

The following Microsoft Graph API permissions are required for this to work:
    Policy.ReadWrite.ConditionalAccess
    Policy.Read.All
    Directory.Read.All
    Agreement.Read.All
    Application.Read.All

Also, the user running this (the one who signs in when the authentication pops up) must have the appropriate permissions in Azure AD (Global Admin, Security Admin, Conditional Access Admin, etc).
#>


# Export your Conditional Access policies to a JSON file for backup.
$Parameters = @{
    ClientID = ''
    ClientSecret = ''
    FilePath = 'C:\Temp\Conditional Access Backup.json'
}

Export-DCConditionalAccessPolicyDesign @Parameters


# Import Conditional Access policies from a JSON file exported by Export-DCConditionalAccessPolicyDesign.
$Parameters = @{
    ClientID = ''
    ClientSecret = ''
    FilePath = 'C:\Temp\Conditional Access Backup.json'
    SkipReportOnlyMode = $false
    DeleteAllExistingPolicies = $false
}

Import-DCConditionalAccessPolicyDesign @Parameters


# Export Conditional Access policy design report to Excel.
$Parameters = @{
    ClientID = ''
    ClientSecret = ''
}

New-DCConditionalAccessPolicyDesignReport @Parameters


# Export Conditional Access Assignment Report to Excel.
$Parameters = @{
    ClientID = ''
    ClientSecret = ''
    IncludeGroupMembers = $false
}

New-DCConditionalAccessAssignmentReport @Parameters


# Learn more about the different Conditional Access commands in DCToolbox.
help Export-DCConditionalAccessPolicyDesign -Full
help Import-DCConditionalAccessPolicyDesign -Full
help New-DCConditionalAccessPolicyDesignReport -Full
help New-DCConditionalAccessAssignmentReport -Full

'@

                Set-Clipboard $Snippet

                Write-Host -ForegroundColor "Yellow" ""
                Write-Host -ForegroundColor "Yellow" "Example copied to clipboard!"
                Write-Host -ForegroundColor "Yellow" ""
            }
            3 {
                $Snippet = @'
# Install required modules (only needed first time).
Install-Module -Name DCToolbox -Scope CurrentUser -Force
Install-Module -Name AzureADPreview -Scope CurrentUser -Force
Install-Package msal.ps -AcceptLicense -Force

# Enable one of your Azure AD PIM roles.
Enable-DCAzureADPIMRole

# Enable multiple Azure AD PIM roles.
Enable-DCAzureADPIMRole -RolesToActivate 'Exchange Administrator', 'Security Reader'

# Fully automate Azure AD PIM role activation.
Enable-DCAzureADPIMRole -RolesToActivate 'Exchange Administrator', 'Security Reader' -UseMaxiumTimeAllowed -Reason 'Performing some Exchange security coniguration according to change #12345.'

<#
    Example output:

    VERBOSE: Connecting to Azure AD...

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


# Learn more about Enable-DCAzureADPIMRole.
help Enable-DCAzureADPIMRole -Full

# Privileged Identity Management | My roles:
# https://portal.azure.com/#blade/Microsoft_Azure_PIMCommon/ActivationMenuBlade/aadmigratedroles

# Privileged Identity Management | Azure AD roles | Overview:
# https://portal.azure.com/#blade/Microsoft_Azure_PIMCommon/ResourceMenuBlade/aadoverview/resourceId//resourceType/tenant/provider/aadroles

'@

                Set-Clipboard $Snippet

                Write-Host -ForegroundColor "Yellow" ""
                Write-Host -ForegroundColor "Yellow" "Example copied to clipboard!"
                Write-Host -ForegroundColor "Yellow" ""
            }
            4 {
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
            5 {
                $Snippet = @'
# README: This script is an example of what you might want to/need to do if your Azure AD has been breached. This script was created in the spirit of the zero trust assume breach methodology. The idea is that if you detect that attackers are already on the inside, then you must try to kick them out. This requires multiple steps and you also must handle other resources like your on-prem AD. However, this script example helps you in the right direction when it comes to Azure AD admin roles.

# More info on my blog: https://danielchronlund.com/2021/03/29/my-azure-ad-has-been-breached-what-now/

break



# *** Connect to Azure AD ***
Import-Module AzureADPreview
Connect-AzureAD



# *** Interesting Azure AD roles to inspect ***
$InterestingDirectoryRoles = 'Global Administrator',
'Global Reader',
'Privileged Role Administrator',
'Security Administrator',
'Application Administrator',
'Compliance Administrator'



# *** Inspect current Azure AD admins (if you use Azure AD PIM) ***

# Fetch tenant ID.
$TenantID = (Get-AzureADTenantDetail).ObjectId

# Fetch all Azure AD role definitions.
$AzureADRoleDefinitions = Get-AzureADMSPrivilegedRoleDefinition -ProviderId "aadRoles" -ResourceId $TenantID | Where-Object { $_.DisplayName -in $InterestingDirectoryRoles }

# Fetch all Azure AD PIM role assignments.
$AzureADDirectoryRoleAssignments = Get-AzureADMSPrivilegedRoleAssignment -ProviderId "aadRoles" -ResourceId $TenantID | Where-Object { $_.RoleDefinitionId -in $AzureADRoleDefinitions.Id }

# Fetch Azure AD role members for each role and format as custom object.
$AzureADDirectoryRoleMembers = foreach ($AzureADDirectoryRoleAssignment in $AzureADDirectoryRoleAssignments) {
    $UserAccountDetails = Get-AzureAdUser -ObjectId $AzureADDirectoryRoleAssignment.SubjectId

    $LastLogon = (Get-AzureAdAuditSigninLogs -top 1 -filter "UserId eq '$($AzureADDirectoryRoleAssignment.SubjectId)'" | Select-Object CreatedDateTime).CreatedDateTime

    if ($LastLogon) {
        $LastLogon = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date -Date $LastLogon), (Get-TimeZone).Id)
    }

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "AzureADDirectoryRole" -Value ($AzureADRoleDefinitions | Where-Object { $_.Id -eq $AzureADDirectoryRoleAssignment.RoleDefinitionId }).DisplayName
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserID" -Value $UserAccountDetails.ObjectID
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserAccount" -Value $UserAccountDetails.DisplayName
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $UserAccountDetails.UserPrincipalName
    $CustomObject | Add-Member -MemberType NoteProperty -Name "AssignmentState" -Value $AzureADDirectoryRoleAssignment.AssignmentState
    $CustomObject | Add-Member -MemberType NoteProperty -Name "AccountCreated" -Value $UserAccountDetails.ExtensionProperty.createdDateTime
    $CustomObject | Add-Member -MemberType NoteProperty -Name "LastLogon" -Value $LastLogon
    $CustomObject
}

# List all Azure AD role members (newest first).
$AzureADDirectoryRoleMembers | Sort-Object AccountCreated -Descending | Format-Table



# *** Inspect current Azure AD admins (only if you do NOT use Azure AD PIM) ***

# Interesting Azure AD roles to inspect.
$InterestingDirectoryRoles = 'Global Administrator',
'Global Reader',
'Privileged Role Administrator',
'Security Administrator',
'Application Administrator',
'Compliance Administrator'

# Fetch Azure AD role details.
$AzureADDirectoryRoles = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -in $InterestingDirectoryRoles }

# Fetch Azure AD role members for each role and format as custom object.
$AzureADDirectoryRoleMembers = foreach ($AzureADDirectoryRole in $AzureADDirectoryRoles) {
    $RoleAssignments = Get-AzureADDirectoryRoleMember -ObjectId $AzureADDirectoryRole.ObjectId

    foreach ($RoleAssignment in $RoleAssignments) {
        $LastLogon = (Get-AzureAdAuditSigninLogs -top 1 -filter "UserId eq '$($RoleAssignment.ObjectId)'" | Select-Object CreatedDateTime).CreatedDateTime

        if ($LastLogon) {
            $LastLogon = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date -Date $LastLogon), (Get-TimeZone).Id)
        }

        $CustomObject = New-Object -TypeName psobject
        $CustomObject | Add-Member -MemberType NoteProperty -Name "AzureADDirectoryRole" -Value $AzureADDirectoryRole.DisplayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "UserID" -Value $RoleAssignment.ObjectID
        $CustomObject | Add-Member -MemberType NoteProperty -Name "UserAccount" -Value $RoleAssignment.DisplayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $RoleAssignment.UserPrincipalName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "AccountCreated" -Value $RoleAssignment.ExtensionProperty.createdDateTime
        $CustomObject | Add-Member -MemberType NoteProperty -Name "LastLogon" -Value $LastLogon
        $CustomObject
    }
}

# List all Azure AD role members (newest first).
$AzureADDirectoryRoleMembers | Sort-Object AccountCreated -Descending | Format-Table



# *** Check if admin accounts are synced from on-prem (bad security) ***

# Loop through the admins from previous output and fetch sync status.
$SyncedAdmins = foreach ($AzureADDirectoryRoleMember in $AzureADDirectoryRoleMembers) {
    $IsSynced = (Get-AzureADUser -ObjectId $AzureADDirectoryRoleMember.UserID | Where-Object {$_.DirSyncEnabled -eq $true}).DirSyncEnabled

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserID" -Value $AzureADDirectoryRoleMember.UserID
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserAccount" -Value $AzureADDirectoryRoleMember.UserAccount
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $AzureADDirectoryRoleMember.UserPrincipalName

    if ($IsSynced) {
        $CustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremAccount" -Value 'True'
    } else {
        $CustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremAccount" -Value 'False'
    }
    
    $CustomObject
}

# List admins (synced on-prem accounts first).
$SyncedAdmins | Sort-Object UserPrincipalName -Descending -Unique | Sort-Object SyncedOnPremAccount -Descending | Format-Table



# *** ON-PREM SYNC PANIC BUTTON: Block all Azure AD admin accounts that are synced from on-prem ***
# WARNING: Make sure you understand what you're doing before running this script!

# Loop through admins synced from on-prem and block sign-ins.
foreach ($SyncedAdmin in ($SyncedAdmins | Where-Object { $_.SyncedOnPremAccount -eq 'True' })) {
    Set-AzureADUser -ObjectID $SyncedAdmin.UserID -AccountEnabled $false
}

# Check account status.
foreach ($SyncedAdmin in ($SyncedAdmins | Where-Object { $_.SyncedOnPremAccount -eq 'True' })) {
    Get-AzureADUser -ObjectID $SyncedAdmin.UserID | Select-Object userPrincipalName, AccountEnabled
}



# *** Check admins last password set time ***

# Connect to Microsoft online services.
Connect-MsolService

# Loop through the admins from previous output and fetch LastPasswordChangeTimeStamp.
$AdminPasswordChanges = foreach ($AzureADDirectoryRoleMember in ($AzureADDirectoryRoleMembers| Sort-Object UserID -Unique)) {
    $LastPasswordChangeTimeStamp = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date -Date (Get-MsolUser -ObjectId $AzureADDirectoryRoleMember.UserID | Select-Object LastPasswordChangeTimeStamp).LastPasswordChangeTimeStamp), (Get-TimeZone).Id)

    $CustomObject = New-Object -TypeName psobject
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserID" -Value $AzureADDirectoryRoleMember.UserID
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserAccount" -Value $AzureADDirectoryRoleMember.UserAccount
    $CustomObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $AzureADDirectoryRoleMember.UserPrincipalName
    $CustomObject | Add-Member -MemberType NoteProperty -Name "LastPasswordChangeTimeStamp" -Value $LastPasswordChangeTimeStamp
    $CustomObject
}

# List admins (newest passwords first).
$AdminPasswordChanges | Sort-Object LastPasswordChangeTimeStamp -Descending | Format-Table



# *** ADMIN PASSWORD PANIC BUTTON: Reset passwords for all Azure AD admins (except for current user and break glass accounts) ***
# WARNING: Make sure you understand what you're doing before running this script!

# IMPORTANT: Define your break glass accounts.
$BreakGlassAccounts = 'breakglass1@example.onmicrosoft.com', 'breakglass2@example.onmicrosoft.com'

# The current user running PowerShell against Azure AD.
$CurrentUser = (Get-AzureADCurrentSessionInfo).Account.Id

# Loop through admins and set new complex passwords (using generated GUIDs).
foreach ($AzureADDirectoryRoleMember in ($AzureADDirectoryRoleMembers | Sort-Object UserPrincipalName -Unique)) {
    if ($AzureADDirectoryRoleMember.UserPrincipalName -notin $BreakGlassAccounts -and $AzureADDirectoryRoleMember.UserPrincipalName -ne $CurrentUser) {
        Write-Verbose -Verbose -Message "Setting new password for $($AzureADDirectoryRoleMember.UserPrincipalName)..."
        Set-AzureADUserPassword -ObjectId $AzureADDirectoryRoleMember.UserID -Password (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)
    } else {
        Write-Verbose -Verbose -Message "Skipping $($AzureADDirectoryRoleMember.UserPrincipalName)!"
    }
}

'@

                Set-Clipboard $Snippet

                Write-Host -ForegroundColor "Yellow" ""
                Write-Host -ForegroundColor "Yellow" "Example copied to clipboard!"
                Write-Host -ForegroundColor "Yellow" ""
            }
            100 {
                $Snippet = @'
X

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
    $Choice = CreateMenu -MenuTitle "Copy DCToolbox example to clipboard" -MenuChoices "Microsoft Graph with PowerShell examples", "Manage Conditional Access as code", "Activate an Azure AD Privileged Identity Management (PIM) role", "General PowerShell script template", "Azure AD Security Breach Kick-Out Process"
    

    # Handle menu choice.
    HandleMenuChoice -MenuChoice $Choice
}



function Connect-DCMsGraphAsDelegated {
    <#
        .SYNOPSIS
            Connect to Microsoft Graph with delegated credentials (interactive login will popup).

        .DESCRIPTION
            This CMDlet will prompt you to sign in to Azure AD. If successfull an access token is returned that can be used with other Graph CMDlets. Make sure you store the access token in a variable according to the example.

            Before running this CMDlet, you first need to register a new application in your Azure AD according to this article:
            https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/
            
        .PARAMETER ClientID
            Client ID for your Azure AD application with Conditional Access Graph permissions.
        
        .PARAMETER ClientSecret
            Client secret for the Azure AD application with Conditional Access Graph permissions.
            
        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            $AccessToken = Connect-DCMsGraphAsDelegated -ClientID '8a85d2cf-17c7-4ecd-a4ef-05b9a81a9bba' -ClientSecret 'j[BQNSi29Wj4od92ritl_DHJvl1sG.Y/'
    #>


    param (
        [parameter(Mandatory = $true)]
        [string]$ClientID,

        [parameter(Mandatory = $true)]
        [string]$ClientSecret
    )


    # Declarations.
    $Resource = "https://graph.microsoft.com"
    $RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"


    # Force TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


    # UrlEncode the ClientID and ClientSecret and URL's for special characters.
    Add-Type -AssemblyName System.Web
    $ClientSecretEncoded = [System.Web.HttpUtility]::UrlEncode($ClientSecret)
    $ResourceEncoded = [System.Web.HttpUtility]::UrlEncode($Resource)
    $RedirectUriEncoded = [System.Web.HttpUtility]::UrlEncode($RedirectUri)


    # Function to popup Auth Dialog Windows Form.
    function Get-AuthCode {
        Add-Type -AssemblyName System.Windows.Forms
        $Form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width = 440; Height = 640 }
        $Web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width = 420; Height = 600; Url = ($Url -f ($Scope -join "%20")) }
        $DocComp = {
            $Global:uri = $Web.Url.AbsoluteUri        
            if ($Global:uri -match "error=[^&]*|code=[^&]*") {
                $Form.Close() 
            }
        }

        $Web.ScriptErrorsSuppressed = $true
        $Web.Add_DocumentCompleted($DocComp)
        $Form.Controls.Add($Web)
        $Form.Add_Shown( { $Form.Activate() })
        $Form.ShowDialog() | Out-Null
        $QueryOutput = [System.Web.HttpUtility]::ParseQueryString($Web.Url.Query)
        $Output = @{ }

        foreach ($Key in $QueryOutput.Keys) {
            $Output["$Key"] = $QueryOutput[$Key]
        }
    }


    # Get AuthCode.
    $Url = "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&redirect_uri=$RedirectUriEncoded&client_id=$ClientID&resource=$ResourceEncoded&prompt=admin_consent&scope=$ScopeEncoded"
    Get-AuthCode


    # Extract Access token from the returned URI.
    $Regex = '(?<=code=)(.*)(?=&)'
    $AuthCode = ($Uri | Select-String -Pattern $Regex).Matches[0].Value


    # Get Access Token.
    $Body = "grant_type=authorization_code&redirect_uri=$RedirectUri&client_id=$ClientId&client_secret=$ClientSecretEncoded&code=$AuthCode&resource=$Resource"
    $TokenResponse = Invoke-RestMethod https://login.microsoftonline.com/common/oauth2/token -Method Post -ContentType "application/x-www-form-urlencoded" -Body $Body -ErrorAction "Stop"


    # Return the access token.
    $TokenResponse.access_token
}



function Connect-DCMsGraphAsApplication {
    <#
        .SYNOPSIS
            Connect to Microsoft Graph with application credentials.

        .DESCRIPTION
            This CMDlet will automatically connect to Microsoft Graph using application permissions (as opposed to delegated credentials). If successfull an access token is returned that can be used with other Graph CMDlets. Make sure you store the access token in a variable according to the example.

            Before running this CMDlet, you first need to register a new application in your Azure AD according to this article:
            https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/
            
        .PARAMETER ClientID
            Client ID for your Azure AD application with Conditional Access Graph permissions.

        .PARAMETER ClientSecret
            Client secret for the Azure AD application with Conditional Access Graph permissions.

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

            Before running this CMDlet, you first need to register a new application in your Azure AD according to this article:
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
        } else {
            $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $GraphUri -UseBasicParsing -Method $GraphMethod -ContentType "application/json" -Body $GraphBody
        }
        
        if ($QueryRequest.value) {
            $QueryResult += $QueryRequest.value
        } else {
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



function Enable-DCAzureADPIMRole {
    <#
        .SYNOPSIS
            Activate an Azure AD Privileged Identity Management (PIM) role with PowerShell.

        .DESCRIPTION
            Uses the Azure AD Preview module and the MSAL module to activate a user selected Azure AD role in Azure AD Privileged Identity Management (PIM) with PowerShell. It uses MSAL to force an MFA prompt, even if not required. This is needed because PIM role activation often requires MFA approval.

            During activation, the user will be primpted to specify a reason for the activation.
        
        .PARAMETER RolesToActivate
            This parameter is optional but if you specify it, you can select multiple roles to activate at ones.

        .PARAMETER Reason
            Specify the reason for activating your roles.

        .PARAMETER UseMaxiumTimeAllowed
            Use this switch to automatically request maxium allowed time for all role assignments.
            
        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            Enable-DCAzureADPIMRole

        .EXAMPLE
            Enable-DCAzureADPIMRole -RolesToActivate 'Exchange Administrator', 'Security Reader'

        .EXAMPLE
            Enable-DCAzureADPIMRole -RolesToActivate 'Exchange Administrator', 'Security Reader' -UseMaxiumTimeAllowed

        .EXAMPLE
            Enable-DCAzureADPIMRole -RolesToActivate 'Exchange Administrator', 'Security Reader' -Reason 'Performing some Exchange security coniguration.' -UseMaxiumTimeAllowed
    #>

    param (
        [parameter(Mandatory = $false)]
        [array]$RolesToActivate = @(),

        [parameter(Mandatory = $false)]
        [string]$Reason,

        [parameter(Mandatory = $false)]
        [switch]$UseMaxiumTimeAllowed
    )

    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"

    # Check if the Azure AD Preview module is installed.
    if (Get-Module -ListAvailable -Name "AzureADPreview") {
        # Do nothing.
    } 
    else {
        Write-Error -Exception "The Azure AD Preview PowerShell module is not installed. Please, run 'Install-Module AzureADPreview -Force' as an admin and try again." -ErrorAction Stop
    }

    # Check if the MSAL module is installed.
    if (Get-Module -ListAvailable -Name "msal.ps") {
        # Do nothing.
    }
    else {
        Write-Error -Exception "The MSAL module is not installed. Please, run 'Install-Package msal.ps -AcceptLicense -Force' as an admin and try again." -ErrorAction Stop
    }

    # Make sure AzureADPreview is the loaded PowerShell module even if AzureAD is installed.
    Remove-Module AzureAD -ErrorAction SilentlyContinue
    Import-Module AzureADPreview

    # Function to check if there already is an active Azure AD session.
    function AzureAdConnected {
        try {
            $Var = Get-AzureADTenantDetail
            $true
        } 
        catch {
            $false
        }
    }

    # Check if already connected to Azure AD.
    if (!(AzureAdConnected)) {
        # Try to force MFA challenge (since it is often required for PIM role activation).

        Write-Verbose -Verbose -Message 'Connecting to Azure AD...'

        # Get token for MS Graph by prompting for MFA.
        $MsResponse = Get-MsalToken -Scopes @('https://graph.microsoft.com/.default') -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" -RedirectUri "urn:ietf:wg:oauth:2.0:oob" -Authority 'https://login.microsoftonline.com/common' -Interactive -ExtraQueryParameters @{claims = '{"access_token" : {"amr": { "values": ["mfa"] }}}' }

        # Get token for AAD Graph.
        $AadResponse = Get-MsalToken -Scopes @('https://graph.windows.net/.default') -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" -RedirectUri "urn:ietf:wg:oauth:2.0:oob" -Authority 'https://login.microsoftonline.com/common'

        $AccountId = $AadResponse.Account.HomeAccountId.ObjectId
        $TenantId = $AadResponse.Account.HomeAccountId.TenantId

        Connect-AzureAD -AadAccessToken $AadResponse.AccessToken -MsAccessToken $MsResponse.AccessToken -AccountId $AccountId -TenantId:  $TenantId | Out-Null
    }

    # Fetch session information.
    $AzureADCurrentSessionInfo = Get-AzureADCurrentSessionInfo

    # Fetch current user object ID.
    $CurrentAccountId = $AzureADCurrentSessionInfo.Account.Id
    $CurrentAccountId = (Get-AzureADUser -ObjectId $CurrentAccountId).ObjectId

    # Fetch all Azure AD role definitions.
    $AzureADMSPrivilegedRoleDefinition = Get-AzureADMSPrivilegedRoleDefinition -ProviderId 'aadRoles' -ResourceId $AzureADCurrentSessionInfo.TenantId.Guid

    # Fetch all Azure AD role settings.
    $AzureADMSPrivilegedRoleSetting = Get-AzureADMSPrivilegedRoleSetting -ProviderId 'aadRoles' -Filter "ResourceId eq '$($AzureADCurrentSessionInfo.TenantId)'"

    # Fetch all PIM role assignments for the current user.
    $AzureADMSPrivilegedRoleAssignment = Get-AzureADMSPrivilegedRoleAssignment -ProviderId "aadRoles" -ResourceId $AzureADCurrentSessionInfo.TenantId -Filter "SubjectId eq '$CurrentAccountId'" | Where-Object { $_.AssignmentState -eq 'Eligible' }

    # Exit if no roles are found.
    if ($AzureADMSPrivilegedRoleAssignment.Count -eq 0) {
        Write-Verbose -Verbose -Message ''
        Write-Verbose -Verbose -Message 'Found no eligible PIM roles to activate :('
        break
    }

    # Format the fetched information.
    $CurrentAccountRoles = foreach ($RoleAssignment in ($AzureADMSPrivilegedRoleAssignment | Select-Object -Unique)) {
        $CustomObject = New-Object -TypeName psobject
        $CustomObject | Add-Member -MemberType NoteProperty -Name 'RoleDefinitionId' -Value $RoleAssignment.RoleDefinitionId
        $CustomObject | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value ($AzureADMSPrivilegedRoleDefinition | Where-Object { $_.Id -eq $RoleAssignment.RoleDefinitionId } ).DisplayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name 'AssignmentState' -Value $RoleAssignment.AssignmentState
        $CustomObject | Add-Member -MemberType NoteProperty -Name 'maximumGrantPeriodInMinutes' -Value ((($AzureADMSPrivilegedRoleSetting | Where-Object { $_.RoleDefinitionId -eq $RoleAssignment.RoleDefinitionId }).UserMemberSettings | Where-Object { $_.RuleIdentifier -eq 'ExpirationRule' }).Setting | ConvertFrom-Json).maximumGrantPeriodInMinutes
        $CustomObject | Add-Member -MemberType NoteProperty -Name 'StartDateTime' -Value $RoleAssignment.StartDateTime
        $CustomObject | Add-Member -MemberType NoteProperty -Name 'EndDateTime' -Value $RoleAssignment.EndDateTime
        $CustomObject
    }

    
    # Write menu title.
    Write-Host -ForegroundColor "Yellow" ""
    Write-Host -ForegroundColor "Yellow" "*** Activate PIM Role ***"
    Write-Host -ForegroundColor "Yellow" ""

    # Check if parameter was specified, and if that is true, enable all roles.
    if(!($RolesToActivate)) {
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
            break
        }

        # Exit if nothing is selected.
        if ($Answer -eq '') {
            break
        }

        # Exit if no role is selected.
        if (!($CurrentAccountRoles[$Answer - 1])) {
            break
        }

        $RolesToActivate = @($CurrentAccountRoles[$Answer - 1])
    } else {
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
        if ($Role.AssignmentState -eq 'Active') {
            Write-Warning -Message "Azure AD Role '$($Role.DisplayName)' already activated!"
        }
        else {
            $Duration = 0

            if ($UseMaxiumTimeAllowed) {
                $Duration = ($Role.maximumGrantPeriodInMinutes / 60)
            } else {
                # Prompt user for duration.
                if (!($Duration = Read-Host "Duration for '$($Role.DisplayName)' [$($Role.maximumGrantPeriodInMinutes / 60) hour(s)]")) { $Duration = ($Role.maximumGrantPeriodInMinutes / 60) }
            }

            # Create activation schedule based on the current role limit.
            $Schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
            $Schedule.Type = "Once"
            $Schedule.StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            $Schedule.endDateTime = ((Get-Date).AddHours($Duration)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

            # Activate PIM role.
            Write-Verbose -Verbose -Message "Activating PIM role '$($Role.DisplayName)'..."
            Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId 'aadRoles' -ResourceId $AzureADCurrentSessionInfo.TenantId -RoleDefinitionId $Role.RoleDefinitionId -SubjectId $CurrentAccountId -Type 'UserAdd' -AssignmentState 'Active' -Schedule $Schedule -Reason $Reason | Out-Null

            Write-Verbose -Verbose -Message "$($Role.DisplayName) has been activated until $($Schedule.endDateTime)!"
        }
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



function Test-DCAzureAdUserExistence {
	<#
        .SYNOPSIS
            Test if an account exists in Azure AD for specified email addresses.
        
        .DESCRIPTION
            This CMDlet will connect to public endpoints in Azure AD to find out if an account exists for specified email addresses or not. This script works without any authentication to Azure AD. This is called user enumeration in cyber security.
            
            The script can't see accounts for federated domains (since they are on-prem accounts) but it will tell you what organisation the federated domain belongs to.

            Do not use this script in an unethical or unlawful way. Use it to find weak spots in you Azure AD configuration.
        
        .PARAMETER Users
            An array of one or more user email addresses to test.

        .PARAMETER UseTorHttpProxy
            Use a running Tor network HTTP proxy that was started by Start-DCTorHttpProxy.
        
        .EXAMPLE
            Test-DCAzureAdUserExistence -UseTorHttpProxy -Users "user1@example.com", "user2@example.com", "user3@example.onmicrosoft.com"
        
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

		# Check if user account exists in Azure AD.
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
			# If the domain is Managed (not federated) we can tell if an account exists in Azure AD :)
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



function Test-DCAzureAdCommonAdmins {
    <#
        .SYNOPSIS
            Test if common and easily guessed admin usernames exist for specified Azure AD domains.
        
        .DESCRIPTION
            Uses Test-DCAzureAdUserExistence to test if common and weak admin account names exist in specified Azure AD domains. It uses publicaly available Microsoft endpoints to query for this information. Run help Test-DCAzureAdUserExistence for more info.

            Do not use this script in an unethical or unlawful way. Use it to find weak spots in you Azure AD configuration.
        
        .PARAMETER Domains
            An array of one or more domains to test.

        .PARAMETER UseTorHttpProxy
            Use a running Tor network HTTP proxy that was started by Start-DCTorHttpProxy.
        
        .EXAMPLE
            Test-DCAzureAdCommonAdmins -UseTorHttpProxy -Domains "example.com", "example2.onmicrosoft.com"
        
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
			Test-DCAzureAdUserExistence -UseTorHttpProxy -Users ($CommonAdminUsernames -replace "DOMAINNAME", $Domain)
		}
		else {
			Test-DCAzureAdUserExistence -Users ($CommonAdminUsernames -replace "DOMAINNAME", $Domain)
		}
	}   
}



function Test-DCLegacyAuthentication {
	<#
        .SYNOPSIS
            Test if legacy authentication is allowed in Office 365 for a particular user.
        
        .DESCRIPTION
            This CMDlet lets you test if legacy authentication is allowed in Office 365. It uses an older reporting endpoints to test the authentication.

            Do not use this script in an unethical or unlawful way. Use it to find weak spots in you Azure AD configuration.
        
        .PARAMETER Credential
            The Azure AD credentials to test.
        
        .EXAMPLE
            Test-DCLegacyAuthentication

        .EXAMPLE
            Test-DCLegacyAuthentication -Credential $Cred

        .EXAMPLE
            if (Test-DCLegacyAuthentication -Credential $Cred) { 'Legacy authentication is allowed :(' }
        
        .INPUTS
            PSCredential

        .OUTPUTS
            None
        
        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
	#>


	param (
		[parameter(Mandatory = $true)]
		[PSCredential]$Credential
	)


    try {
        Write-Verbose -Verbose -Message "Testing legacy authentication for $($Credential.UserName)..."
        Invoke-WebRequest -Uri "https://reports.office365.com/ecp/reportingwebservice/reporting.svc" -Credential $Credential | Out-Null


        Write-Host -ForegroundColor 'Red' "ALLOWED: Legacy authentication is allowed for $($Credential.UserName) in Office 365! This is very dangerous!"


        # Return true if legacy authentication is allowed..
        $true
    } catch {
        if ($_.ErrorDetails.Message -like "*401*" -or $_.ErrorDetails.Message -like "*403*") {
            Write-Host -ForegroundColor 'Green' "AUTHENTICATION FAILED: Legacy authentication failed for $($Credential.UserName) in Office 365!"
        } else {
            Write-Error $_.ErrorDetails.Message
        }


        # Return false if legacy authentication is blocked..
        $false
    }
}



function Export-DCConditionalAccessPolicyDesign {
    <#
        .SYNOPSIS
            Export all Conditional Access policies to JSON.

        .DESCRIPTION
            This CMDlet uses Microsoft Graph to export all Conditional Access policies in the tenant to a JSON file. This JSON file can be used for backup, documentation or to deploy the same policies again with Import-DCConditionalAccessPolicyDesign. You can treat Conditional Access as code!

            Before running this CMDlet, you first need to register a new application in your Azure AD according to this article:
            https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/

            The following Microsoft Graph API permissions are required for this script to work:
                Policy.ReadWrite.ConditionalAccess
                Policy.Read.All
                Directory.Read.All
                Agreement.Read.All
                Application.Read.All
            
            Also, the user running this CMDlet (the one who signs in when the authentication pops up) must have the appropriate permissions in Azure AD (Global Admin, Security Admin, Conditional Access Admin, etc).
            
        .PARAMETER ClientID
            Client ID for the Azure AD application with Conditional Access Microsoft Graph permissions.

        .PARAMETER ClientSecret
            Client secret for the Azure AD application with Conditional Access Microsoft Graph permissions.

        .PARAMETER FilePath
            The file path where the new JSON file will be created. Skip to use the current path.

        .INPUTS
            None

        .OUTPUTS
            JSON file with all Conditional Access policies.

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            $Parameters = @{
                ClientID = ''
                ClientSecret = ''
                FilePath = 'C:\Temp\Conditional Access.json'
            }

            Export-DCConditionalAccessPolicyDesign @Parameters
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $true)]
        [string]$ClientID,

        [parameter(Mandatory = $true)]
        [string]$ClientSecret,

        [parameter(Mandatory = $false)]
        [string]$FilePath = "$((Get-Location).Path)\Conditional Access Backup $(Get-Date -Format 'yyyy-MM-dd').json"
    )


    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Authenticate to Microsoft Graph.
    Write-Verbose -Verbose -Message "Connecting to Microsoft Graph..."
    $AccessToken = Connect-DCMsGraphAsDelegated -ClientID $ClientID -ClientSecret $ClientSecret


    # Export all Conditional Access policies from Microsoft Graph as JSON.
    Write-Verbose -Verbose -Message "Exporting Conditional Access policies to '$FilePath'..."
    
    $GraphUri = 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies'

    Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri | Sort-Object createdDateTime | ConvertTo-Json -Depth 10 | Out-File -Force:$true -FilePath $FilePath

    # Perform some clean up in the file.
    $CleanUp = Get-Content $FilePath | Select-String -Pattern '"id":', '"createdDateTime":', '"modifiedDateTime":' -notmatch

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

            WARNING: If you want to, you can also delete all existing policies when deploying your new ones with -DeleteAllExistingPolicies, Use this parameter with causon and allways create a backup with Export-DCConditionalAccessPolicyDesign first!

            Before running this CMDlet, you first need to register a new application in your Azure AD according to this article:
            https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/

            The following Microsoft Graph API permissions are required for this script to work:
                Policy.ReadWrite.ConditionalAccess
                Policy.Read.All
                Directory.Read.All
                Agreement.Read.All
                Application.Read.All
            
            Also, the user running this CMDlet (the one who signs in when the authentication pops up) must have the appropriate permissions in Azure AD (Global Admin, Security Admin, Conditional Access Admin, etc).

            As a best practice you should always have an Azure AD security group with break glass accounts excluded from all Conditional Access policies.
            
        .PARAMETER ClientID
            Client ID for the Azure AD application with Conditional Access Microsoft Graph permissions.

        .PARAMETER ClientSecret
            Client secret for the Azure AD application with Conditional Access Microsoft Graph permissions.

        .PARAMETER FilePath
            The file path of the JSON file containing your Conditional Access policies.

        .PARAMETER SkipReportOnlyMode
            All Conditional Access policies created by this CMDlet will be set to report-only mode if you don't use this parameter.

        .PARAMETER DeleteAllExistingPolicies
            WARNING: If you want to, you can delete all existing policies when deploying your new ones with -DeleteAllExistingPolicies, Use this parameter with causon and allways create a backup with Export-DCConditionalAccessPolicyDesign first!!
            
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
                ClientID = ''
                ClientSecret = ''
                FilePath = 'C:\Temp\Conditional Access.json'
                SkipReportOnlyMode = $false
                DeleteAllExistingPolicies = $false
            }

            Import-DCConditionalAccessPolicyDesign @Parameters
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $true)]
        [string]$ClientID,

        [parameter(Mandatory = $true)]
        [string]$ClientSecret,

        [parameter(Mandatory = $true)]
        [string]$FilePath,

        [parameter(Mandatory = $false)]
        [switch]$SkipReportOnlyMode,

        [parameter(Mandatory = $false)]
        [switch]$DeleteAllExistingPolicies
    )


    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Authenticate to Microsoft Graph.
    Write-Verbose -Verbose -Message "Connecting to Microsoft Graph..."
    $AccessToken = Connect-DCMsGraphAsDelegated -ClientID $ClientID -ClientSecret $ClientSecret


    # Import policies from JSON file.
    Write-Verbose -Verbose -Message "Importing JSON from '$FilePath'..."
    $ConditionalAccessPolicies = Get-Content -Raw -Path $FilePath


    # Modify enabled policies to report-only if not skipped with -SkipReportOnlyMode.
    if (!($SkipReportOnlyMode)) {
        Write-Verbose -Verbose -Message "Setting all new policys to report-only mode..."
        $ConditionalAccessPolicies = $ConditionalAccessPolicies -replace '"enabled"', '"enabledForReportingButNotEnforced"'
    }


    # Delete all existing policies if -DeleteAllExistingPolicies is specified.
    if ($DeleteAllExistingPolicies) {
        Write-Verbose -Verbose -Message "Deleting all existing Conditional Access policies..."
        $GraphUri = 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies'
        $ExistingPolicies = Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri -ErrorAction SilentlyContinue

        foreach ($Policy in $ExistingPolicies) {
            Start-Sleep -Seconds 1
            $GraphUri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($Policy.id)"

            Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'DELETE' -GraphUri $GraphUri -ErrorAction SilentlyContinue | Out-Null
        }
    }


    # URI for creating Conditional Access policies.
    $GraphUri = 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies'

    $ConditionalAccessPolicies = $ConditionalAccessPolicies | ConvertFrom-Json

    foreach ($Policy in $ConditionalAccessPolicies) {
        Start-Sleep -Seconds 1
        Write-Verbose -Verbose -Message "Creating '$($Policy.DisplayName)'..."

        try {
            # Create new policies.
            Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'POST' -GraphUri $GraphUri -GraphBody ($Policy | ConvertTo-Json -Depth 10) | Out-Null
        }
        catch {
            Write-Error -Message $_.Exception.Message -ErrorAction Continue
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

            Before running this CMDlet, you first need to register a new application in your Azure AD according to this article:
            https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/

            The following Microsoft Graph API permissions are required for this script to work:
                Policy.ReadWrite.ConditionalAccess
                Policy.Read.All
                Directory.Read.All
                Agreement.Read.All
                Application.Read.All
            
            The CMDlet also uses the PowerShell Excel Module for the export to Excel. You can install this module with:
            Install-Module ImportExcel

            The report is exported to Excel and will automatically open. In Excel, please do this:
            1. Select all cells.
            2. Click on "Wrap Text".
            3. Click on "Top Align".

            The report is now easier to read.
            
            Also, the user running this CMDlet (the one who signs in when the authentication pops up) must have the appropriate permissions in Azure AD (Global Admin, Security Admin, Conditional Access Admin, etc).
            
        .PARAMETER ClientID
            Client ID for the Azure AD application with Conditional Access Microsoft Graph permissions.

        .PARAMETER ClientSecret
            Client secret for the Azure AD application with Conditional Access Microsoft Graph permissions.

        .INPUTS
            None

        .OUTPUTS
            Excel report with all Conditional Access policies.

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            $Parameters = @{
                ClientID = ''
                ClientSecret = ''
            }

            New-DCConditionalAccessPolicyDesignReport @Parameters
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $true)]
        [string]$ClientID,

        [parameter(Mandatory = $true)]
        [string]$ClientSecret
    )


    # Set Error Action - Possible choices: Stop, SilentlyContinue
    $ErrorActionPreference = "Stop"



    # ----- [Execution] -----

    # Check if the Excel module is installed.
    if (Get-Module -ListAvailable -Name "ImportExcel") {
        # Do nothing.
    }
    else {
        Write-Error -Exception "The Excel PowerShell module is not installed. Please, run 'Install-Module ImportExcel' as an admin and try again." -ErrorAction Stop
    }


    # Authenticate to Microsoft Graph.
    Write-Verbose -Verbose -Message "Connecting to Microsoft Graph..."
    $AccessToken = Connect-DCMsGraphAsDelegated -ClientID $ClientID -ClientSecret $ClientSecret


    # Export all Conditional Access policies from Microsoft Graph as JSON.
    Write-Verbose -Verbose -Message "Generating Conditional Access policy design report..."
    

    # Fetch conditional access policies.
    $GraphUri = 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies'
    $CAPolicies = Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri | Sort-Object createdDateTime


    # Fetch service principals for id translation.
    $GraphUri = 'https://graph.microsoft.com/beta/servicePrincipals'
    $EnterpriseApps = Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri


    # Fetch roles for id translation.
    $GraphUri = 'https://graph.microsoft.com/beta/directoryRoles'
    $AzureADRoles = Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri


    # Format the result.
    $Result = foreach ($Policy in $CAPolicies) {
        $CustomObject = New-Object -TypeName psobject


        # displayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "displayName" -Value (Out-String -InputObject $Policy.displayName)


        # state
        $CustomObject | Add-Member -MemberType NoteProperty -Name "state" -Value (Out-String -InputObject $Policy.state)


        # includeUsers
        $Users = foreach ($User in $Policy.conditions.users.includeUsers) {
            if ($User -ne 'All' -and $User -ne 'GuestsOrExternalUsers'-and $User -ne 'None') {
                $GraphUri = "https://graph.microsoft.com/beta/users/$User"
                (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).userPrincipalName
            } else {
                $User
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeUsers" -Value (Out-String -InputObject $Users)


        # excludeUsers
        $Users = foreach ($User in $Policy.conditions.users.excludeUsers) {
            if ($User -ne 'All' -and $User -ne 'GuestsOrExternalUsers'-and $User -ne 'None') {
                $GraphUri = "https://graph.microsoft.com/beta/users/$User"
                (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).userPrincipalName
            } else {
                $User
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeUsers" -Value (Out-String -InputObject $Users)


        # includeGroups
        $Groups = foreach ($Group in $Policy.conditions.users.includeGroups) {
            if ($Group -ne 'All' -and $Group -ne 'None') {
                $GraphUri = "https://graph.microsoft.com/beta/groups/$Group"
                (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).displayName
            } else {
                $Group
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeGroups" -Value (Out-String -InputObject $Groups)


        # excludeGroups
        $Groups = foreach ($Group in $Policy.conditions.users.excludeGroups) {
            if ($Group -ne 'All' -and $Group -ne 'None') {
                $GraphUri = "https://graph.microsoft.com/beta/groups/$Group"
                (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).displayName
            } else {
                $Group
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeGroups" -Value (Out-String -InputObject $Groups)


        # includeRoles
        $Roles = foreach ($Role in $Policy.conditions.users.includeRoles) {
            if ($Role -ne 'None' -and $Role -ne 'All') {
                $RoleToCheck = ($AzureADRoles | Where-Object { $_.roleTemplateId -eq $Role }).displayName

                if ($RoleToCheck) {
                    $RoleToCheck
                } else {
                    $Role
                }
            } else {
                $Role
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeRoles" -Value (Out-String -InputObject $Roles)


        # excludeRoles
        $Roles = foreach ($Role in $Policy.conditions.users.excludeRoles) {
            if ($Role -ne 'None' -and $Role -ne 'All') {
                $RoleToCheck = ($AzureADRoles | Where-Object { $_.roleTemplateId -eq $Role }).displayName

                if ($RoleToCheck) {
                    $RoleToCheck
                } else {
                    $Role
                }
            } else {
                $Role
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeRoles" -Value (Out-String -InputObject $Roles)


        # includeApplications
        $Applications = foreach ($Application in $Policy.conditions.applications.includeApplications) {
            if ($Application -ne 'None' -and $Application -ne 'All' -and $Application -ne 'Office365') {
                ($EnterpriseApps | Where-Object { $_.appID -eq $Application }).displayName
            } else {
                $Application
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeApplications" -Value (Out-String -InputObject $Applications)


        # excludeApplications
        $Applications = foreach ($Application in $Policy.conditions.applications.excludeApplications) {
            if ($Application -ne 'None' -and $Application -ne 'All' -and $Application -ne 'Office365') {
                ($EnterpriseApps | Where-Object { $_.appID -eq $Application }).displayName
            } else {
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
                $GraphUri = "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations/$includeLocation"
                (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).displayName
            } elseif ($includeLocation -eq '00000000-0000-0000-0000-000000000000') {
                'MFA Trusted IPs'
            } else {
                $includeLocation
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeLocations" -Value (Out-String -InputObject $includeLocations)


        # excludeLocation
        $excludeLocations = foreach ($excludeLocation in $Policy.conditions.locations.excludeLocations) {
            if ($excludeLocation -ne 'All' -and $excludeLocation -ne 'AllTrusted' -and $excludeLocation -ne '00000000-0000-0000-0000-000000000000') {
                $GraphUri = "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations/$excludeLocation"
                (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).displayName
            } elseif ($excludeLocation -eq '00000000-0000-0000-0000-000000000000') {
                'MFA Trusted IPs'
            } else {
                $excludeLocation
            }
        }


        # excludeLocations
        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeLocations" -Value (Out-String -InputObject $excludeLocations)


        # grantControls
        $CustomObject | Add-Member -MemberType NoteProperty -Name "grantControls" -Value (Out-String -InputObject $Policy.grantControls.builtInControls)


        # termsOfUse
        $TermsOfUses = foreach ($TermsOfUse in $Policy.grantControls.termsOfUse) {
            $GraphUri = "https://graph.microsoft.com/beta/agreements/$TermsOfUse"
            (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).displayName
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

            The purpose of the report is to give you an overview of how Conditional Access policies are currently applied in an Azure AD tenant, and which users are targeted by which policies.

            The report does not include information about the policies themselves. Use New-DCConditionalAccessPolicyDesignReport for that task.

            Before running this CMDlet, you first need to register a new application in your Azure AD according to this article:
            https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/

            The following Microsoft Graph API permissions are required for this script to work:
                Policy.Read.ConditionalAccess
                Policy.Read.All
                Directory.Read.All
                Group.Read.All

            The CMDlet also uses the PowerShell Excel Module for the export to Excel. You can install this module with:
            Install-Module ImportExcel

            The report is exported to Excel and will automatically open. In Excel, please do this:
            1. Select all cells.
            2. Click on "Wrap Text".
            3. Click on "Top Align".

            The report is now easier to read.

            More information can be found here: https://danielchronlund.com/2020/10/20/export-your-conditional-access-policy-assignments-to-excel/
            
        .PARAMETER ClientID
            Client ID for the Azure AD application with Conditional Access Microsoft Graph permissions.

        .PARAMETER ClientSecret
            Client secret for the Azure AD application with Conditional Access Microsoft Graph permissions.

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
            $ClientID = ''
            $ClientSecret = ''

            New-DCConditionalAccessAssignmentReport -ClientID $ClientID -ClientSecret $ClientSecret -IncludeGroupMembers
    #>



    # ----- [Initialisations] -----

    # Script parameters.
    param (
        [parameter(Mandatory = $true)]
        [string]$ClientID,

        [parameter(Mandatory = $true)]
        [string]$ClientSecret,

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
        Write-Error -Exception "The Excel PowerShell module is not installed. Please, run 'Install-Module ImportExcel' as an admin and try again." -ErrorAction Stop
    }


    # Connect to Microsoft Graph.
    Write-Verbose -Verbose -Message "Connecting to Microsoft Graph..."
    $AccessToken = Connect-DCMsGraphAsDelegated -ClientID $ClientID -ClientSecret $ClientSecret


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
            (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).displayName
        }
        
        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeGroupsDisplayName" -Value $includeGroupsDisplayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeGroupsId" -Value $Policy.conditions.users.includeGroups


        Write-Verbose -Verbose -Message "Getting exclude groups for policy $($Policy.displayName)..."
        $excludeGroupsDisplayName = foreach ($Object in $Policy.conditions.users.excludeGroups) {
            $GraphUri = "https://graph.microsoft.com/v1.0/groups/$Object"
            (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri).displayName
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeGroupsDisplayName" -Value $excludeGroupsDisplayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeGroupsId" -Value $Policy.conditions.users.excludeGroups


        Write-Verbose -Verbose -Message "Getting include users for policy $($Policy.displayName)..."
        $includeUsersUserPrincipalName = foreach ($Object in $Policy.conditions.users.includeUsers) {
            if ($Object -ne "All" -and $Object -ne "GuestsOrExternalUsers" -and $Object -ne "None") {
                $GraphUri = "https://graph.microsoft.com/v1.0/users/$Object"
                (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri -ErrorAction "Continue").userPrincipalName
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
                (Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri -ErrorAction "Continue").userPrincipalName
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
            $RoleInfo = Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri
            
            if ($RoleInfo.displayName) {
                $RoleInfo.displayName
            } else {
                $Object
            }
        }
        
        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeRolesDisplayName" -Value $includeRolesDisplayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "includeRolesId" -Value $Policy.conditions.users.includeRoles


        Write-Verbose -Verbose -Message "Getting exclude roles for policy $($Policy.displayName)..."
        $excludeRolesDisplayName = foreach ($Object in $Policy.conditions.users.excludeRoles) {
            $GraphUri = "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=$Object"
            $RoleInfo = Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri $GraphUri
            
            if ($RoleInfo.displayName) {
                $RoleInfo.displayName
            } else {
                $Object
            }
        }

        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeRolesDisplayName" -Value $excludeRolesDisplayName
        $CustomObject | Add-Member -MemberType NoteProperty -Name "excludeRolesId" -Value $Policy.conditions.users.excludeRoles


        $CustomObject
    }


    # Fetch include group members from Azure AD:
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


    # Fetch exclude group members from Azure AD:
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
