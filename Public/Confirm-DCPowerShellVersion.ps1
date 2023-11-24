
function Confirm-DCPowerShellVersion {
    <#
        .SYNOPSIS
            Check that a supported PowerShell version is running.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/

        .EXAMPLE
            Confirm-DCPowerShellVersion

        .EXAMPLE
            Confirm-DCPowerShellVersion -Verbose
    #>


    [CmdletBinding()]
    param ()


    Write-Verbose -Message "Checking PowerShell version..."
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Error -Message "Please upgrade to PowerShell version 7 before running this command: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.3"

        return
    } else {
        Write-Verbose -Message "PowerShell $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor) found!"
    }
}
