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
