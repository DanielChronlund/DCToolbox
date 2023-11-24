function Install-DCToolbox {
    <#
        .SYNOPSIS
            Check, install, and update the DCToolbox PowerShell module.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            Install-DCToolbox

        .EXAMPLE
            Install-DCToolbox -Verbose
    #>


    [CmdletBinding()]
    param ()


    Write-Verbose -Message "Looking for DCToolbox PowerShell module..."

    $ModuleVersion = [string](Get-Module -ListAvailable -Name DCToolbox -Verbose:$false | Sort-Object Version -Descending | Select-Object -First 1).Version
    $LatestVersion = (Find-Module DCToolbox -Verbose:$false | Select-Object -First 1).Version

    if (!($ModuleVersion)) {
        Write-Verbose -Message "Not found! Installing DCToolbox $LatestVersion..."
        Install-Module DCToolbox -Scope CurrentUser -Force -Verbose:$false
        Write-Verbose -Message "Done!"
    } elseif ($ModuleVersion -ne $LatestVersion) {
        Write-Verbose -Message "Found DCToolbox $ModuleVersion. Upgrading to $LatestVersion..."
        Install-Module DCToolbox -Scope CurrentUser -Force -Verbose:$false
        Write-Verbose -Message "Done!"
    } else {
        Write-Verbose -Message "DCToolbox $ModuleVersion found!"
    }

    Remove-Module DCToolbox -Verbose:$false -ErrorAction SilentlyContinue | Out-Null
}
