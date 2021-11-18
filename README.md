# DCToolbox

A PowerShell toolbox for Microsoft 365 security fans.

Author: Daniel Chronlund

---------------------------------------------------

<h2>Introduction</h2>

This PowerShell module contains a collection of tools for Microsoft 365 security tasks, Microsoft Graph functions, Azure AD management, Conditional Access, zero trust strategies, attack and defense scenarios, etc.

---------------------------------------------------

<h2>Get Started</h2>

Install the module from the PowerShell Gallery by running:

<b>Install-Module DCToolbox</b>

If you already installed it, update to the latest version by running:

<b>Update-Module DCToolbox</b>

PowerShell Gallery package link: https://www.powershellgallery.com/packages/DCToolbox

When you have installed it, to get started, run:

<b>Get-DCHelp</b>

Explore and copy script examples to your clipboard with:

<b>Copy-DCExample</b>

---------------------------------------------------

<h2>Included Tools</h2>

<h3>Connect-DCMsGraphAsDelegated</h3>

Gather basic configuration data from a Microsoft 365 tenant.

<h3>Connect-DCMsGraphAsDelegated</h3>

Connect to Microsoft Graph with delegated credentials (interactive login will popup).

<h3>Connect-DCMsGraphAsApplication</h3>

Connect to Microsoft Graph with application credentials.

<h3>Invoke-DCMsGraphQuery</h3>

Run a Microsoft Graph query.

<h3>Enable-DCAzureADPIMRole</h3>

Activate one or more Azure AD Privileged Identity Management (PIM) role with PowerShell.

<h3>Get-DCPublicIp</h3>

Get current public IP address information. You can use the -UseTorHttpProxy to route traffic through a running Tor network HTTP proxy that was started by Start-DCTorHttpProxy.

<h3>Start-DCTorHttpProxy</h3>

Start a Tor network HTTP proxy that can be used for anonymization of HTTP traffic in PowerShell. Requires proxy support in the PowerShell CMDlet you want to anonymise. Many of the tools included in DCToolbox supports this.

<h3>Test-DCAzureAdUserExistence</h3>

Test if an account exists in Azure AD for specified email addresses.

<h3>Test-DCAzureAdCommonAdmins</h3>

Test if common and easily guessed admin usernames exist for specified Azure AD domains.

<h3>Test-DCLegacyAuthentication</h3>

Test if legacy authentication is allowed in Office 365 for a particular user.

<h3>Get-DCAzureADUsersAndGroupsAsGuest</h3>

Lets a guest user enumerate users and security groups/teams when 'Guest user access restrictions' in Azure AD is set to the default configuration.

<h3>Export-DCConditionalAccessPolicyDesign</h3>

This CMDlet uses Microsoft Graph to export all Conditional Access policies in the tenant to a JSON file. This JSON file can be used for backup, documentation or to deploy the same policies again with Import-DCConditionalAccessPolicyDesign.

<h3>Import-DCConditionalAccessPolicyDesign</h3>

This CMDlet uses Microsoft Graph to automatically create Conditional Access policies from a JSON file. The JSON file can be created from existing policies with Export-DCConditionalAccessPolicyDesign or manually by following the syntax described in the Microsoft Graph documentation.

<h3>New-DCConditionalAccessPolicyDesignReport</h3>

Automatically generate an Excel report containing your current Conditional Access policy design.

<h3>New-DCConditionalAccessAssignmentReport</h3>

Automatically generate an Excel report containing your current Conditional Access assignments.

---------------------------------------------------

Please follow me on my blog https://danielchronlund.com, on LinkedIn and on Twitter!

@DanielChronlund
