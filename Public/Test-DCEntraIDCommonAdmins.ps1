function Test-DCEntraIDCommonAdmins {
    <#
        .SYNOPSIS
            Test if common and easily guessed admin usernames exist for specified Entra ID domains.

        .DESCRIPTION
            Uses Test-DCEntraIDUserExistence to test if common and weak admin account names exist in specified Entra ID domains. It uses publicaly available Microsoft endpoints to query for this information. Run help Test-DCEntraIDUserExistence for more info.

            Do not use this script in an unethical or unlawful way. Use it to find weak spots in you Entra ID configuration.

        .PARAMETER Domains
            An array of one or more domains to test.

        .PARAMETER UseTorHttpProxy
            Use a running Tor network HTTP proxy that was started by Start-DCTorHttpProxy.

        .EXAMPLE
            Test-DCEntraIDCommonAdmins -UseTorHttpProxy -Domains "example.com", "example2.onmicrosoft.com"

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
        [array]$Domains,

        [parameter(Mandatory = $false)]
        [switch]$UseTorHttpProxy
    )

    $CommonAdminUsernames = "admin@DOMAINNAME",
    "administrator@DOMAINNAME",
    "root@DOMAINNAME",
    "system@DOMAINNAME",
    "operator@DOMAINNAME",
    "super@DOMAINNAME",
    "breakglass@DOMAINNAME",
    "breakglass1@DOMAINNAME",
    "breakglass2@DOMAINNAME",
    "serviceaccount@DOMAINNAME",
    "service@DOMAINNAME",
    "srv@DOMAINNAME",
    "svc@DOMAINNAME",
    "smtp@DOMAINNAME",
    "smtprelay@DOMAINNAME",
    "mail@DOMAINNAME",
    "exchange@DOMAINNAME",
    "sharepoint@DOMAINNAME",
    "teams@DOMAINNAME",
    "azure@DOMAINNAME",
    "user@DOMAINNAME",
    "user1@DOMAINNAME",
    "user01@DOMAINNAME",
    "guest@DOMAINNAME",
    "test@DOMAINNAME",
    "test1@DOMAINNAME",
    "test01@DOMAINNAME",
    "testing@DOMAINNAME",
    "test.test@DOMAINNAME",
    "test.testsson@DOMAINNAME",
    "demo@DOMAINNAME",
    "backup@DOMAINNAME",
    "print@DOMAINNAME",
    "sa@DOMAINNAME",
    "sql@DOMAINNAME",
    "mysql@DOMAINNAME",
    "oracle@DOMAINNAME"

    foreach ($Domain in $Domains) {
        if ($UseTorHttpProxy) {
            Test-DCEntraIDUserExistence -UseTorHttpProxy -Users ($CommonAdminUsernames -replace "DOMAINNAME", $Domain)
        }
        else {
            Test-DCEntraIDUserExistence -Users ($CommonAdminUsernames -replace "DOMAINNAME", $Domain)
        }
    }
}