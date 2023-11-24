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