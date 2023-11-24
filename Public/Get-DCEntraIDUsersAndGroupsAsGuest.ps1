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