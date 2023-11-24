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