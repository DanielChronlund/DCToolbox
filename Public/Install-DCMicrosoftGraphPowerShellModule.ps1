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

    $ModuleVersion = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication -Verbose:$false | Select-Object -First 1

    if (!($ModuleVersion)) {
        Write-Verbose -Message "Not found! Installing the Graph PowerShell module..."
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -Verbose:$false
    } elseif (($ModuleVersion).Version.Major -lt 2 -and ($ModuleVersion).Version.Minor -lt 8) {
        Write-Verbose -Message "Found version $(($ModuleVersion).Version.Major).$(($ModuleVersion).Version.Minor). Upgrading..."
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -Verbose:$false
    } else {
        Write-Verbose -Message "Graph PowerShell $(($ModuleVersion).Version.Major).$(($ModuleVersion).Version.Minor) found!"
    }
}
