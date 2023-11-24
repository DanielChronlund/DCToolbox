
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