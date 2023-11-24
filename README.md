# DCToolbox

A PowerShell toolbox for Microsoft 365 security fans.

*Author: Daniel Chronlund (https://danielchronlund.com)*

---------------------------------------------------


## About DCToolbox

This PowerShell module contains a collection of tools for Microsoft 365 security tasks, Microsoft Graph functions, Entra ID management, Conditional Access, zero trust strategies, attack and defense scenarios, etc.

---------------------------------------------------


## Get Started

Install the module from the PowerShell Gallery by running:

    Install-Module DCToolbox

If you already installed it, update to the latest version by running:

    Update-Module DCToolbox

PowerShell Gallery package link: https://www.powershellgallery.com/packages/DCToolbox

When you have installed it, to get started, run:

    Get-DCHelp

Explore and copy script examples to your clipboard with:

    Copy-DCExample

---------------------------------------------------

## Included Tools

### Add-DCConditionalAccessPoliciesBreakGlassGroup

**Synopsis:**

Excludes a specified Entra ID security group from all Conditional Access policies in the tenant.

**Details:**

Excludes a specified Entra ID security group from all Conditional Access policies in the tenant.

Please create the group and add your break glass accounts before running this command.

You can filter on a name prefix with -PrefixFilter.

**Parameters:**

	-PrefixFilter
	Description:	Only modify the policies with this prefix.
	Required:		false
	
	-ExcludeGroupName
	Description:	The name of your exclude group in Entra ID. Please create the group and add your break glass accounts before running this command.
	Required:		true
	
**Examples:**

	    
	Add-DCConditionalAccessPoliciesBreakGlassGroup -PrefixFilter 'GLOBAL - ' -ExcludeGroupName 'Excluded from Conditional Access'

---

### Confirm-DCPowerShellVersion

**Synopsis:**

Check that a supported PowerShell version is running.

**Details:**



**Parameters:**

**Examples:**

	    
	Confirm-DCPowerShellVersion
	    
	Confirm-DCPowerShellVersion -Verbose

---

### Connect-DCMsGraphAsApplication

**Synopsis:**

Connect to Microsoft Graph with application credentials.

**Details:**

This CMDlet will automatically connect to Microsoft Graph using application permissions (as opposed to delegated credentials). If successfull an access token is returned that can be used with other Graph CMDlets. Make sure you store the access token in a variable according to the example.

Before running this CMDlet, you first need to register a new application in your Entra ID according to this article:
https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/

**Parameters:**

	-ClientID
	Description:	Client ID for your Entra ID application.
	Required:		true
	
	-ClientSecret
	Description:	Client secret for the Entra ID application.
	Required:		true
	
	-TenantName
	Description:	The name of your tenant (example.onmicrosoft.com).
	Required:		true
	
**Examples:**

	    
	$AccessToken = Connect-DCMsGraphAsApplication -ClientID '8a85d2cf-17c7-4ecd-a4ef-05b9a81a9bba' -ClientSecret 'j[BQNSi29Wj4od92ritl_DHJvl1sG.Y/' -TenantName 'example.onmicrosoft.com'

---

### Connect-DCMsGraphAsUser

**Synopsis:**

Connect to Microsoft Graph with the Microsoft Graph PowerShell module as a user (using delegated permissions in Graph).

**Details:**



**Parameters:**

	-Scopes
	Description:	The required API permission scopes (delegated permissions). Example: "Policy.ReadWrite.ConditionalAccess", "Policy.Read.All"
	Required:		true
	
**Examples:**

	    
	Connect-DCMsGraphAsUser -Scopes 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All'
	    
	Connect-DCMsGraphAsUser -Scopes 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Directory.Read.All' -Verbose

---

### Copy-DCExample

**Synopsis:**


Copy-DCExample 


**Details:**



**Parameters:**

**Examples:**


---

### Deploy-DCConditionalAccessBaselinePoC

**Synopsis:**

Automatically deploy the latest version of the Conditional Access policy design baseline from https://danielchronlund.com.

**Details:**

This CMDlet downloads the latest version of the Conditional Access policy design baseline from https://danielchronlund.com/2020/11/26/azure-ad-conditional-access-policy-design-baseline-with-automatic-deployment-support/. It creates all necessary dependencies like exclusion groups, named locations, and terms of use, and then deploys all Conditional Access policies in the baseline.

All Conditional Access policies created by this CMDlet will be set to report-only mode.

The purpose of this tool is to quickly deploy the complete baseline as a PoC. You can then test, pilot, and deploy it going forward.

You must be a Global Admin to run this command (because of the admin consent required) but no other preparations are required.

**Parameters:**

	-AddCustomPrefix
	Description:	Adds a custom prefix to all policy names.
	Required:		false
	
	-ExcludeGroupDisplayName
	Description:	Set a custom name for the break glass exclude group. Default: 'Excluded from Conditional Access'. You can set this to an existing group if you already have one.
	Required:		false
	
	-ServiceAccountGroupDisplayName
	Description:	Set a custom name for the service account group. Default: 'Conditional Access Service Accounts'. You can set this to an existing group if you already have one.
	Required:		false
	
	-NamedLocationCorpNetwork
	Description:	Set a custom name for the corporate network named location. Default: 'Corporate Network'. You can set this to an existing named location if you already have one.
	Required:		false
	
	-NamedLocationAllowedCountries
	Description:	Set a custom name for the allowed countries named location. Default: 'Allowed Countries'. You can set this to an existing named location if you already have one.
	Required:		false
	
	-TermsOfUseName
	Description:	Set a custom name for the terms of use. Default: 'Terms of Use'. You can set this to an existing Terms of Use if you already have one.
	Required:		false
	
	-SkipPolicies
	Description:	Specify one or more policy names in the baseline that you want to skip.
	Required:		false
	
	-SkipReportOnlyMode
	Description:	All Conditional Access policies created by this CMDlet will be set to report-only mode if you don't use this parameter. WARNING: Use this parameter with caution since ALL POLICIES will go live for ALL USERS when you specify this.
	Required:		false
	
**Examples:**

	    
	Deploy-DCConditionalAccessBaselinePoC
	    
	Deploy-DCConditionalAccessBaselinePoC -AddCustomPrefix 'PILOT - '
	Deploy-DCConditionalAccessBaselinePoC @Parameters    
	# Customize names of dependencies.
	$Parameters = @{
	    ExcludeGroupDisplayName = 'Excluded from Conditional Access'
	    ServiceAccountGroupDisplayName = 'Conditional Access Service Accounts'
	    NamedLocationCorpNetwork = 'Corporate Network'
	    NamedLocationAllowedCountries = 'Allowed Countries'
	    TermsOfUseName = 'Terms of Use'
	}
	    
	Deploy-DCConditionalAccessBaselinePoC -SkipPolicies "GLOBAL - BLOCK - High-Risk Sign-Ins", "GLOBAL - BLOCK - High-Risk Users", "GLOBAL - GRANT - Medium-Risk Sign-Ins", "GLOBAL - GRANT - Medium-Risk Users"
	    
	Deploy-DCConditionalAccessBaselinePoC -SkipReportOnlyMode # WARNING: USE WITH CAUTION!

---

### Enable-DCEntraIDPIMRole

**Synopsis:**

Activate an Entra ID Privileged Identity Management (PIM) role with PowerShell.

**Details:**

Uses the Graph PowerShell module to activate a user selected Entra ID role in Entra ID Privileged Identity Management (PIM).

During activation, the user will be prompted to specify a reason for the activation.

**Parameters:**

	-RolesToActivate
	Description:	This parameter is optional but if you specify it, you can select multiple roles to activate at ones.
	Required:		false
	
	-Reason
	Description:	Specify the reason for activating your roles.
	Required:		false
	
	-UseMaximumTimeAllowed
	Description:	Use this switch to automatically request maximum allowed time for all role assignments.
	Required:		false
	
**Examples:**

	    
	Enable-DCEntraIDPIMRole
	    
	Enable-DCEntraIDPIMRole -RolesToActivate 'Exchange Administrator', 'Security Reader'
	    
	Enable-DCEntraIDPIMRole -RolesToActivate 'Exchange Administrator', 'Security Reader' -UseMaximumTimeAllowed
	    
	Enable-DCEntraIDPIMRole -RolesToActivate 'Exchange Administrator', 'Security Reader' -Reason 'Performing some Exchange security configuration.' -UseMaximumTimeAllowed

---

### Export-DCConditionalAccessPolicyDesign

**Synopsis:**

Export all Conditional Access policies to JSON.

**Details:**

This CMDlet uses Microsoft Graph to export all Conditional Access policies in the tenant to a JSON file. This JSON file can be used for backup, documentation or to deploy the same policies again with Import-DCConditionalAccessPolicyDesign. You can basically treat Conditional Access as code!

The user running this CMDlet (the one who signs in when the authentication pops up) must have the appropriate permissions in Entra ID (Global Admin, Security Admin, Conditional Access Admin, etc).

**Parameters:**

	-FilePath
	Description:	The file path where the new JSON file will be created. Skip this to use the current path.
	Required:		false
	
	-PrefixFilter
	Description:	Only export the policies with this prefix.
	Required:		false
	
**Examples:**

	    
	Export-DCConditionalAccessPolicyDesign
	    
	$Parameters = @{
	    FilePath = 'C:\Temp\Conditional Access.json'
	}
	Export-DCConditionalAccessPolicyDesign @Parameters
	    
	$Parameters = @{
	    FilePath = 'C:\Temp\Conditional Access.json'
	    PrefixFilter = 'GLOBAL - '
	}
	Export-DCConditionalAccessPolicyDesign @Parameters

---

### Get-DCConditionalAccessPolicies

**Synopsis:**

List all Conditional Access policies in the tenant.

**Details:**

List all Conditional Access policies in the tenant.

You can filter on a name prefix with -PrefixFilter.

**Parameters:**

	-PrefixFilter
	Description:	Only show the policies with this prefix.
	Required:		false
	
	-ShowTargetResources
	Description:	Show included and excluded resources in output. Only relevant without -Details.
	Required:		false
	
	-Details
	Description:	Include policy details in output.
	Required:		false
	
	-NamesOnly
	Description:	Show names only in output.
	Required:		false
	
**Examples:**

	    
	Get-DCConditionalAccessPolicies
	    
	Get-DCConditionalAccessPolicies -PrefixFilter 'GLOBAL - '

---

### Get-DCEntraIDUsersAndGroupsAsGuest

**Synopsis:**

This script lets a guest user enumerate users and security groups/teams when 'Guest user access restrictions' in Entra ID is set to the default configuration.

**Details:**

This script is a proof of concept. Don't use it for bad things! It lets a guest user enumerate users and security groups/teams when 'Guest user access restrictions' in Entra ID is set to the default configuration. It works around the limitation that guest users must do explicit lookups for users and groups. It basically produces a list of all users and groups in the tenant, even though such actions are blocked for guests by default.

If the target tenant allows guest users to sign in with Entra ID PowerShell, and the 'Guest user access restrictions' is set to one of these two settings:
'Guest users have the same access as members (most inclusive)'
'Guest users have limited access to properties and memberships of directory objects' [default]

And not set to:
'Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)'

...then this script will query Entra ID for the group memberships of the specified -InterestingUsers that you already know the UPN of. It then perform nested queries until all users and groups have been found. It will stop after a maximum of 5 iterations to avoid throttling and infinite loops. "A friend of a friend of a friend..."

Finally, the script will output one array with found users, and one array with found groups/teams. You can then export them to CSV or some other format of your choice. Export examples are outputed for your convenience.

**Parameters:**

	-TenantId
	Description:	The tenant ID of the target tenant where you are a guest. You can find all your guest tenant IDs here: https://portal.azure.com/#settings/directory
	Required:		true
	
	-AccountId
	Description:	Your UPN in your home tenant (probably your email address, right?).
	Required:		true
	
	-InterestingUsers
	Description:	One or more UPNs of users in the target tenant. These will serve as a starting point for the search, and one or two employees you know about is often sufficient to enumerate everything.
	Required:		true
	
**Examples:**

	    
	Get-DCEntraIDUsersAndGroupsAsGuest -TenantId '00000000-0000-0000-0000-000000000000' -AccountId 'user@example.com' -InterestingUsers 'customer1@customer.com', 'customer2@customer.com'

---

### Get-DCHelp

**Synopsis:**


Get-DCHelp 


**Details:**



**Parameters:**

**Examples:**


---

### Get-DCNamedLocations

**Synopsis:**

List Named Locations in the tenant.

**Details:**

List Named Locations in the tenant.

You can filter on a name prefix with -PrefixFilter.

**Parameters:**

	-PrefixFilter
	Description:	Only show the named locations with this prefix.
	Required:		false
	
**Examples:**

	    
	Get-DCNamedLocations
	    
	Get-DCNamedLocations -PrefixFilter 'OFFICE-'
	    
	# List all trusted IP addresses.
	(Get-DCNamedLocations | where isTrusted -eq $true).ipRanges | Select-Object -Unique | Sort-Object
	    
	# List all countries.
	(Get-DCNamedLocations).countriesAndRegions | Select-Object -Unique | Sort-Object

---

### Get-DCPublicIp

**Synopsis:**

Get current public IP address information.

**Details:**

Get the current public IP address and related information. The ipinfo.io API is used to fetch the information. You can use the -UseTorHttpProxy to route traffic through a running Tor network HTTP proxy that was started by Start-DCTorHttpProxy.

**Parameters:**

	-UseTorHttpProxy
	Description:	Route traffic through a running Tor network HTTP proxy that was started by Start-DCTorHttpProxy.
	Required:		false
	
**Examples:**

	    
	Get-DCPublicIp
	    
	(Get-DCPublicIp).ip
	    
	Write-Host "$((Get-DCPublicIp).city) $((Get-DCPublicIp).country)"

---

### Import-DCConditionalAccessPolicyDesign

**Synopsis:**

Import Conditional Access policies from JSON.

**Details:**

This CMDlet uses Microsoft Graph to automatically create Conditional Access policies from a JSON file.

The JSON file can be created from existing policies with Export-DCConditionalAccessPolicyDesign or manually by following the syntax described in the Microsoft Graph documentation:
https://docs.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-1.0

All Conditional Access policies created by this CMDlet will be set to report-only mode if you don't use the -SkipReportOnlyMode override.

WARNING: If you want to, you can also delete all existing policies when deploying your new ones with -DeleteAllExistingPolicies, Use this parameter with caution and always create a backup with Export-DCConditionalAccessPolicyDesign first!

The user running this CMDlet (the one who signs in when the authentication pops up) must have the appropriate permissions in Entra ID (Global Admin, Security Admin, Conditional Access Admin, etc).

As a best practice you should always have an Entra ID security group with break glass accounts excluded from all Conditional Access policies.

**Parameters:**

	-FilePath
	Description:	The file path of the JSON file containing your Conditional Access policies.
	Required:		true
	
	-SkipReportOnlyMode
	Description:	All Conditional Access policies created by this CMDlet will be set to report-only mode if you don't use this parameter.
	Required:		false
	
	-DeleteAllExistingPolicies
	Description:	WARNING: If you want to, you can delete all existing policies when deploying your new ones with -DeleteAllExistingPolicies, Use this parameter with causon and allways create a backup with Export-DCConditionalAccessPolicyDesign first!!
	Required:		false
	
	-AddCustomPrefix
	Description:	Adds a custom prefix to all policy names.
	Required:		false
	
	-PrefixFilter
	Description:	Only import (and delete) the policies with this prefix in the JSON file.
	Required:		false
	
**Examples:**

	Import-DCConditionalAccessPolicyDesign @Parameters    
	$Parameters = @{
	    FilePath = 'C:\Temp\Conditional Access.json'
	    SkipReportOnlyMode = $false
	    DeleteAllExistingPolicies = $false
	}
	Import-DCConditionalAccessPolicyDesign @Parameters    
	$Parameters = @{
	    FilePath = 'C:\Temp\Conditional Access.json'
	    SkipReportOnlyMode = $false
	    DeleteAllExistingPolicies = $false
	    AddCustomPrefix = 'PILOT - '
	}
	Import-DCConditionalAccessPolicyDesign @Parameters    
	$Parameters = @{
	    FilePath = 'C:\Temp\Conditional Access.json'
	    SkipReportOnlyMode = $true
	    DeleteAllExistingPolicies = $true
	    PrefixFilter = 'GLOBAL - '
	}

---

### Install-DCMicrosoftGraphPowerShellModule

**Synopsis:**

Check, install, and update the Microsoft Graph PowerShell module.

**Details:**



**Parameters:**

**Examples:**

	    
	Install-DCMicrosoftGraphPowerShellModule
	    
	Install-DCMicrosoftGraphPowerShellModule -Verbose

---

### Install-DCToolbox

**Synopsis:**

Check, install, and update the DCToolbox PowerShell module.

**Details:**



**Parameters:**

**Examples:**

	    
	Install-DCToolbox
	    
	Install-DCToolbox -Verbose

---

### Invoke-DCConditionalAccessSimulation

**Synopsis:**

Simulates the Entra ID Conditional Access evaluation process of a specific scenario.

**Details:**

Uses Microsoft Graph to fetch all Entra ID Conditional Access policies. It then evaluates which policies that would have been applied if this was a real sign-in to Entra ID. Use the different parameters available to specify the conditions. Details are included under each parameter.

**Parameters:**

	-JSONFile
	Description:	Only use this parameter if you want to analyze a local JSON file export of Conditional Access polices, instead of a live tenant. Point it to the local JSON file. Export JSON with Export-DCConditionalAccessPolicyDesign (or any other tool exporting Conditional Access policies from Microsoft Graph to JSON), like 'Entra Exporter'.
	Required:		false
	
	-UserPrincipalName
	Description:	The UPN of the simulated Entra ID user signing in. Can also be set to 'All' for all users, or 'GuestsOrExternalUsers' to test external user sign-in scenarios. Example: 'user@example.com'. Default: 'All'.
	Required:		false
	
	-ApplicationDisplayName
	Description:	The display name of the application targeted by Conditional Access policies (same display name as in Entra ID Portal when creating Conditional Access policies). Example 1: 'Office 365'. Example 2: 'Microsoft Admin Portals'. Default: 'All'.
	Required:		false
	
	-UserAction
	Description:	Under construction...
	Required:		false
	
	-ClientApp
	Description:	The client app type used during sign-in. Possible values: 'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'easSupported', 'other'. Default: 'browser'
	Required:		false
	
	-TrustedIPAddress
	Description:	Specify if the simulated sign-in comes from a trusted IP address (marked as trusted in Named Locations)? $true or $false? Don't specify the actual IP address. That is not really that important when simulating policy evaluation. Default: $false
	Required:		false
	
	-Country
	Description:	The country code for the sign-in country of origin based on IP address geo data. By default, this script tries to resolve the IP address of the current PowerShell session.
	Required:		false
	
	-Platform
	Description:	Specify the OS platform of the client signing in. Possible values: 'all', 'android', 'iOS', 'windows', 'windowsPhone', 'macOS', 'linux', 'spaceRocket'. Default: 'windows'
	Required:		false
	
	-SignInRiskLevel
	Description:	Specify the Entra ID Protection sign-in risk level. Possible values: 'none', 'low', 'medium', 'high'. Default: 'none'
	Required:		false
	
	-UserRiskLevel
	Description:	Specify the Entra ID Protection user risk level. Possible values: 'none', 'low', 'medium', 'high'. Default: 'none'
	Required:		false
	
	-SummarizedOutput
	Description:	By default, this script returns PowerShell objects representing all applied Conditional Access policies only. This can be used for piping to other tools, etc. But sometimes you also want a simple answer of what would happen during the simulated policy evaluation. Specify this parameter to add a summarized and simplified output (outputs to 'Informational' stream with Write-Host).
	Required:		false
	
	-VerbosePolicyEvaluation
	Description:	Include detailed verbose policy evaluation info. Use for troubleshooting and debugging.
	Required:		false
	
	-IncludeNonMatchingPolicies
	Description:	Also, include all policies that did not match, and therefor was not applied. This can be useful to produce different kinds of Conditional Access reports.
	Required:		false
	
**Examples:**

	    
	# Run basic evaluation with default settings.
	Invoke-DCConditionalAccessSimulation | Format-List
	Invoke-DCConditionalAccessSimulation @Parameters    
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
	    
	# Run basic evaluation offline against a JSON of Conditional Access policies.
	Invoke-DCConditionalAccessSimulation -JSONFile 'Conditional Access Backup.json' | Format-List

---

### Invoke-DCEntraIDDeviceAuthFlow

**Synopsis:**

Get a refresh token (or access token) from Entra ID using device code flow.

**Details:**

This CMDlet will start a device code flow authentication process in Entra ID. Go to the provided URL and enter the code to authenticate. The script will wait for the authentication and then return the refresh token, and also copy it to the clipboard.

A refresh token fetched by this tool can be replayed on another device.

**Parameters:**

	-ShowTokenDetails
	Description:	Add this parameter if you want to display the token details on successful authentication.
	Required:		false
	
	-ReturnAccessTokenInsteadOfRefreshToken
	Description:	Return an access token instead of a refresh token.
	Required:		false
	
	-ClientID
	Description:	OPTIONAL: Specify the client ID for which a refresh token should be requested. Defaults to 'Microsoft Azure PowerShell' (1950a258-227b-4e31-a9cf-717495945fc2). If you set this parameter, you must also specify -TenantID. Note that the app registration in Entra ID must have device code flow enabled under Authentication > Advanced settings.
	Required:		false
	
	-TenantID
	Description:	OPTIONAL: Specify your tenant ID. You only need to specify this if you're specifying a ClientID with -ClientID. This is because Microsoft needs to now in which tenant a specific app is located.
	Required:		false
	
**Examples:**

	    
	Invoke-DCEntraIDDeviceAuthFlow
	    
	$RefreshToken = Invoke-DCEntraIDDeviceAuthFlow
	    
	Invoke-DCEntraIDDeviceAuthFlow -ShowTokenDetails
	    
	Invoke-DCEntraIDDeviceAuthFlow -ClientID '' -TenantID ''

---

### Invoke-DCHuntingQuery

**Synopsis:**

Connect to Microsoft Graph with the Microsoft Graph PowerShell module and run a KQL hunting query in Microsoft Defender XDR.

**Details:**

Connect to Microsoft Graph with the Microsoft Graph PowerShell module and run a KQL hunting query in Microsoft Defender XDR.

**Parameters:**

	-Query
	Description:	The KQL query you want to run in Microsoft Defender XDR.
	Required:		true
	
	-IncludeKQLQueryAtTop
	Description:	
	Required:		false
	
	-IncludeRaw
	Description:	Include the raw formated and escaped KQL query sent to Microsoft Graph.
	Required:		false
	
**Examples:**

	Invoke-DCHuntingQuery -Query $Query    
	$Query = @'
	DeviceEvents
	| where ActionType startswith "Asr"
	| summarize count() by ActionType
	| order by count_
	'@
	Invoke-DCHuntingQuery -Query $Query -IncludeKQLQueryAtTop    
	$Query = @'
	DeviceEvents
	| where ActionType startswith "Asr"
	| summarize count() by ActionType
	| order by count_
	'@

---

### Invoke-DCM365DataExfiltration

**Synopsis:**

This script uses an Entra ID app registration to download all files from all M365 groups (Teams) document libraries in a tenant.

**Details:**

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

**Parameters:**

	-ClientID
	Description:	Client ID for your Entra ID application.
	Required:		true
	
	-ClientSecret
	Description:	Client secret for the Entra ID application.
	Required:		true
	
	-TenantName
	Description:	The name of your tenant (example.onmicrosoft.com).
	Required:		true
	
	-WhatIf
	Description:	Skip the actual downloads. It will still show the output and what would have been downloaded.
	Required:		false
	
**Examples:**

	    
	Invoke-M365DataExfiltration -ClientID '8a85d2cf-17c7-4ecd-a4ef-05b9a81a9bba' -ClientSecret 'j[BQNSi29Wj4od92ritl_DHJvl1sG.Y/' -TenantName 'example.onmicrosoft.com'
	    
	Invoke-M365DataExfiltration -ClientID '8a85d2cf-17c7-4ecd-a4ef-05b9a81a9bba' -ClientSecret 'j[BQNSi29Wj4od92ritl_DHJvl1sG.Y/' -TenantName 'example.onmicrosoft.com' -WhatIf

---

### Invoke-DCM365DataWiper

**Synopsis:**

This script uses an Entra ID app registration to wipe all files from all M365 groups (Teams) document libraries in a tenant.

**Details:**

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

**Parameters:**

	-ClientID
	Description:	Client ID for your Entra ID application.
	Required:		true
	
	-ClientSecret
	Description:	Client secret for the Entra ID application.
	Required:		true
	
	-TenantName
	Description:	The name of your tenant (example.onmicrosoft.com).
	Required:		true
	
	-WhatIf
	Description:	Skip the actual deletion. It will still show the output and what would have been deleted.
	Required:		false
	
**Examples:**

	    
	Invoke-DCM365DataWiper -ClientID '8a85d2cf-17c7-4ecd-a4ef-05b9a81a9bba' -ClientSecret 'j[BQNSi29Wj4od92ritl_DHJvl1sG.Y/' -TenantName 'example.onmicrosoft.com'
	    
	Invoke-DCM365DataWiper -ClientID '8a85d2cf-17c7-4ecd-a4ef-05b9a81a9bba' -ClientSecret 'j[BQNSi29Wj4od92ritl_DHJvl1sG.Y/' -TenantName 'example.onmicrosoft.com' -WhatIf

---

### Invoke-DCMsGraphQuery

**Synopsis:**

Run a Microsoft Graph query.

**Details:**

This CMDlet will run a query against Microsoft Graph and return the result. It will connect using an access token generated by Connect-DCMsGraphAsDelegated or Connect-DCMsGraphAsApplication (depending on what permissions you use in Graph).

Before running this CMDlet, you first need to register a new application in your Entra ID according to this article:
https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/

**Parameters:**

	-AccessToken
	Description:	An access token generated by Connect-DCMsGraphAsDelegated or Connect-DCMsGraphAsApplication (depending on what permissions you use in Graph).
	Required:		true
	
	-GraphMethod
	Description:	The HTTP method for the Graph call, like GET, POST, PUT, PATCH, DELETE. Default is GET.
	Required:		false
	
	-GraphUri
	Description:	The Microsoft Graph URI for the query. Example: https://graph.microsoft.com/v1.0/users/
	Required:		true
	
	-GraphBody
	Description:	The request body of the Graph call. This is often used with methids like POST, PUT and PATCH. It is not used with GET.
	Required:		false
	
**Examples:**

	    
	Invoke-DCMsGraphQuery -AccessToken $AccessToken -GraphMethod 'GET' -GraphUri 'https://graph.microsoft.com/v1.0/users/'

---

### New-DCConditionalAccessAssignmentReport

**Synopsis:**

Automatically generate an Excel report containing your current Conditional Access assignments.

**Details:**

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

**Parameters:**

	-IncludeGroupMembers
	Description:	If you include the -IncludeGroupMembers parameter, members of assigned groups will be included in the report as well (of course, this can produce a very large report if you have included large groups in your policy assignments).
	Required:		false
	
**Examples:**

	    
	New-DCConditionalAccessAssignmentReport
	    
	New-DCConditionalAccessAssignmentReport -IncludeGroupMembers

---

### New-DCConditionalAccessPolicyDesignReport

**Synopsis:**

Automatically generate an Excel report containing your current Conditional Access policy design.

**Details:**

Uses Microsoft Graph to fetch all Conditional Access policies and exports an Excel report, You can use the report as documentation, design document, or to get a nice overview of all your policies.

The CMDlet also uses the PowerShell Excel Module for the export to Excel. You can install this module with:
Install-Module ImportExcel -Force

The report is exported to Excel and will automatically open. In Excel, please do this:
1. Select all cells.
2. Click on "Wrap Text".
3. Click on "Top Align".

The report is now easier to read.

The user running this CMDlet (the one who signs in when the authentication pops up) must have the appropriate permissions in Entra ID (Global Admin, Security Admin, Conditional Access Admin, etc).

**Parameters:**

**Examples:**

	    
	New-DCConditionalAccessPolicyDesignReport

---

### New-DCEntraIDAppPermissionsReport

**Synopsis:**

Generate a report containing all Entra ID Enterprise Apps and App Registrations with API permissions (application permissions only) in the tenant.

**Details:**

Uses Microsoft Graph to fetch all Entra ID Enterprise Apps and App Registrations with API permissions (application permissions only) and generate a report. The report includes app names, API permissions, secrets/certificates, and app owners.

The purpose is to find vulnerable applications and API permissions in Entra ID.

Applications marked with 'AppHostedInExternalTenant = False' also has a corresponding App Registration in this tenant. This means that App Registration Owners has the same permissions as the application.

**Parameters:**

**Examples:**

	    
	# Get all API application permissions assigned to applications in tenant.
	New-DCEntraIDAppPermissionsReport
	    
	# Look for sensitive permissions.
	$Result = New-DCEntraIDAppPermissionsReport
	$Result | where RoleName -in 'RoleManagement.ReadWrite.Directory', 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All'
	    
	# Export report to Excel for further filtering and analysis.
	$Result = New-DCEntraIDAppPermissionsReport
	$Path = "$((Get-Location).Path)\Entra ID Enterprise Apps Report $(Get-Date -Format 'yyyy-MM-dd').xlsx"
	$Result | Export-Excel -Path $Path -WorksheetName "Enterprise Apps" -BoldTopRow -FreezeTopRow -AutoFilter -AutoSize -ClearSheet -Show

---

### New-DCEntraIDStaleAccountReport

**Synopsis:**

Automatically generate an Excel report containing all stale Entra ID accounts.

**Details:**

Uses Microsoft Graph to fetch all Entra ID users who has not signed in for a specific number of days, and exports an Excel report. Some users might not have a last sign-in timestamp at all (maybe they didn't sign in or maybe they signed in a very long time ago), but they are still included in the report.

Before running this CMDlet, you first need to register a new application in your Entra ID according to this article:
https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/

The following Microsoft Graph API permissions are required for this script to work:
    Directory.Read.All
    AuditLog.Read.All

The CMDlet also uses the PowerShell Excel Module for the export to Excel. You can install this module with:
Install-Module ImportExcel -Force

Also, the user running this CMDlet (the one who signs in when the authentication pops up) must have the appropriate permissions in Entra ID (Global Admin, Global Reader, Security Admin, Security Reader, etc).

**Parameters:**

	-ClientID
	Description:	Client ID for the Entra ID application with Microsoft Graph permissions.
	Required:		true
	
	-ClientSecret
	Description:	Client secret for the Entra ID application with Microsoft Graph permissions.
	Required:		true
	
	-LastSeenDaysAgo
	Description:	Specify the number of days ago the account was last seen. Note that you can only see as long as your Entra ID sign-in logs reach (30 days by default).
	Required:		false
	
	-OnlyMembers
	Description:	Only include member accounts (no guest accounts) in the report.
	Required:		false
	
	-OnlyGuests
	Description:	Only include guest accounts (no member accounts) in the report.
	Required:		false
	
	-IncludeMemberOf
	Description:	Add a column with all group/teams memberships.
	Required:		false
	
**Examples:**

	New-DCEntraIDStaleAccountReport @Parameters
	
	
	$Parameters = @{
	    ClientID = ''
	    ClientSecret = ''
	    LastSeenDaysAgo = 10
	    OnlyGuests = $true
	    IncludeMemberOf = $true
	}
	New-DCEntraIDStaleAccountReport @Parameters    
	$Parameters = @{
	    ClientID = ''
	    ClientSecret = ''
	    LastSeenDaysAgo = 30
	}

---

### Remove-DCConditionalAccessPolicies

**Synopsis:**

Delete ALL Conditional Access policies in a tenant.

**Details:**

This script is a proof of concept and for testing purposes only. Do not use this script in an unethical or unlawful way. Don’t be stupid!

This CMDlet uses Microsoft Graph to automatically delete all Conditional Access policies in a tenant. It was primarily created to clean-up lab tenants, and as an attack PoC.

This CMDlet will prompt you for confirmation multiple times before deleting policies.

**Parameters:**

	-PrefixFilter
	Description:	Only delete the policies with this prefix.
	Required:		false
	
**Examples:**

	    
	Remove-DCConditionalAccessPolicies
	    
	Remove-DCConditionalAccessPolicies -PrefixFilter 'TEST - '

---

### Rename-DCConditionalAccessPolicies

**Synopsis:**

Rename Conditional Access policies that matches a specific prefix.

**Details:**

This command helps you to quickly rename a bunch of Conditional Access policies by searching for a specific prefix.

If you dontt specify a PrefixFilter, ALL policies will be modified to include the new prefix .

**Parameters:**

	-PrefixFilter
	Description:	Only toggle the policies with this prefix.
	Required:		false
	
	-AddCustomPrefix
	Description:	Adds a custom prefix to all policy names.
	Required:		true
	
**Examples:**

	    
	Rename-DCConditionalAccessPolicies -PrefixFilter 'PILOT - ' -AddCustomPrefix 'PROD - '
	    
	Rename-DCConditionalAccessPolicies -PrefixFilter 'GLOBAL - ' -AddCustomPrefix 'REPORT - GLOBAL - '
	    
	Rename-DCConditionalAccessPolicies -AddCustomPrefix 'OLD - '

---

### Set-DCConditionalAccessPoliciesPilotMode

**Synopsis:**

Toggles Conditional Access policies between 'All users' and a specified pilot group.

**Details:**

This command helps you to quickly toggle you Conditional Access policies between a pilot and production. It does this by switching policies targeting a specified pilot group and 'All users'.

It is common to use a dedicated Entra ID security group to target specific pilot users during a Conditional Access deployment project. When the pilot is completed you want to move away from that pilot group and target 'All users' in the organization instead (at least with your global baseline).

You must filter the toggle with a prefix filter to only modify specific policies. Use a prefix like "GLOBAL -" or "PILOT -" for easy bulk management. This is a built-in safety measure.

**Parameters:**

	-PrefixFilter
	Description:	Only toggle the policies with this prefix.
	Required:		true
	
	-PilotGroupName
	Description:	The name of your pilot group in Entra ID (must be a security group for users).
	Required:		true
	
	-EnablePilot
	Description:	Modify all specified Conditional Access policies to target your pilot group.
	Required:		false
	
	-EnableProduction
	Description:	Modify all specified Conditional Access policies to target 'All users'.
	Required:		false
	
**Examples:**

	    
	Set-DCConditionalAccessPoliciesPilotMode -PrefixFilter 'GLOBAL - ' -PilotGroupName 'Conditional Access Pilot' -EnablePilot
	    
	Set-DCConditionalAccessPoliciesPilotMode -PrefixFilter 'GLOBAL - ' -PilotGroupName 'Conditional Access Pilot' -EnableProduction

---

### Set-DCConditionalAccessPoliciesReportOnlyMode

**Synopsis:**

Toggles Conditional Access policies between 'Report-only' and Enabled.

**Details:**

This command helps you to quickly toggle you Conditional Access policies between Report-only and Enabled.

If will skip any policies in Disabled state.

You must filter the toggle with a prefix filter to only modify specific policies. This is a built-in safety measure.

**Parameters:**

	-PrefixFilter
	Description:	Only toggle the policies with this prefix.
	Required:		true
	
	-SetToReportOnly
	Description:	Modify all specified Conditional Access policies to report-only.
	Required:		false
	
	-SetToEnabled
	Description:	Modify all specified Conditional Access policies to Enabled.
	Required:		false
	
**Examples:**

	    
	Set-DCConditionalAccessPoliciesReportOnlyMode -PrefixFilter 'GLOBAL - ' -SetToReportOnly
	    
	Set-DCConditionalAccessPoliciesReportOnlyMode -PrefixFilter 'GLOBAL - ' -SetToEnabled

---

### Start-DCTorHttpProxy

**Synopsis:**

Start a Tor network HTTP proxy for anonymous HTTP calls via PowerShell.

**Details:**

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

**Parameters:**

	-TorBrowserPath
	Description:	The path to the Tor browser directory. Default is 'C:\Temp\Tor Browser'.
	Required:		false
	
**Examples:**

	    
	Start-DCTorHttpProxy

---

### Test-DCEntraIDCommonAdmins

**Synopsis:**

Test if common and easily guessed admin usernames exist for specified Entra ID domains.

**Details:**

Uses Test-DCEntraIDUserExistence to test if common and weak admin account names exist in specified Entra ID domains. It uses publicaly available Microsoft endpoints to query for this information. Run help Test-DCEntraIDUserExistence for more info.

Do not use this script in an unethical or unlawful way. Use it to find weak spots in you Entra ID configuration.

**Parameters:**

	-Domains
	Description:	An array of one or more domains to test.
	Required:		true
	
	-UseTorHttpProxy
	Description:	Use a running Tor network HTTP proxy that was started by Start-DCTorHttpProxy.
	Required:		false
	
**Examples:**

	    
	Test-DCEntraIDCommonAdmins -UseTorHttpProxy -Domains "example.com", "example2.onmicrosoft.com"

---

### Test-DCEntraIDUserExistence

**Synopsis:**

Test if an account exists in Entra ID for specified email addresses.

**Details:**

This CMDlet will connect to public endpoints in Entra ID to find out if an account exists for specified email addresses or not. This script works without any authentication to Entra ID. This is called user enumeration in cyber security.

The script can't see accounts for federated domains (since they are on-prem accounts) but it will tell you what organisation the federated domain belongs to.

Do not use this script in an unethical or unlawful way. Use it to find weak spots in you Entra ID configuration.

**Parameters:**

	-Users
	Description:	An array of one or more user email addresses to test.
	Required:		true
	
	-UseTorHttpProxy
	Description:	Use a running Tor network HTTP proxy that was started by Start-DCTorHttpProxy.
	Required:		false
	
**Examples:**

	    
	Test-DCEntraIDUserExistence -UseTorHttpProxy -Users "user1@example.com", "user2@example.com", "user3@example.onmicrosoft.com"

---


Please follow me on my blog https://danielchronlund.com, on LinkedIn and on X!

@DanielChronlund
