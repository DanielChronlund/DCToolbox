@{
    AliasesToExport      = @()
    Author               = 'Daniel Chronlund'
    CmdletsToExport      = @()
    CompanyName          = 'Daniel Chronlund'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2023 Daniel Chronlund. All rights reserved.'
    Description          = 'A PowerShell toolbox for Microsoft 365 security fans.'
    FunctionsToExport    = @('Add-DCConditionalAccessPoliciesBreakGlassGroup', 'Confirm-DCPowerShellVersion', 'Connect-DCMsGraphAsApplication', 'Connect-DCMsGraphAsUser', 'Copy-DCExample', 'Deploy-DCConditionalAccessBaselinePoC', 'Enable-DCEntraIDPIMRole', 'Export-DCConditionalAccessPolicyDesign', 'Get-DCConditionalAccessPolicies', 'Get-DCEntraIDUsersAndGroupsAsGuest', 'Get-DCHelp', 'Get-DCNamedLocations', 'Get-DCPublicIp', 'Import-DCConditionalAccessPolicyDesign', 'Install-DCMicrosoftGraphPowerShellModule', 'Install-DCToolbox', 'Invoke-DCConditionalAccessSimulation', 'Invoke-DCEntraIDDeviceAuthFlow', 'Invoke-DCHuntingQuery', 'Invoke-DCM365DataExfiltration', 'Invoke-DCM365DataWiper', 'Invoke-DCMsGraphQuery', 'New-DCConditionalAccessAssignmentReport', 'New-DCConditionalAccessPolicyDesignReport', 'New-DCEntraIDAppPermissionsReport', 'New-DCEntraIDStaleAccountReport', 'Remove-DCConditionalAccessPolicies', 'Rename-DCConditionalAccessPolicies', 'Set-DCConditionalAccessPoliciesPilotMode', 'Set-DCConditionalAccessPoliciesReportOnlyMode', 'Start-DCTorHttpProxy', 'Test-DCEntraIDCommonAdmins', 'Test-DCEntraIDUserExistence')
    GUID                 = '306a16db-02a0-43da-a70c-9e43f9433450'
    ModuleVersion        = '2.0.18'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ExternalModuleDependencies = @('Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Archive', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management')
            ProjectUri                 = 'https://github.com/DanielChronlund/DCToolbox'
            Tags                       = @('Security', 'EntraID')
        }
    }
    RequiredModules      = @(@{
            Guid          = '467f54f2-44a8-4993-8e75-b96c3e443098'
            ModuleName    = 'Microsoft.Graph.Applications'
            ModuleVersion = '2.6.1'
        }, @{
            Guid          = '883916f2-9184-46ee-b1f8-b6a2fb784cee'
            ModuleName    = 'Microsoft.Graph.Authentication'
            ModuleVersion = '2.6.1'
        }, @{
            Guid          = '50bc9e18-e281-4208-8913-c9e1bef6083d'
            ModuleName    = 'Microsoft.Graph.Groups'
            ModuleVersion = '2.6.1'
        }, @{
            Guid          = 'c767240d-585c-42cb-bb2f-6e76e6d639d4'
            ModuleName    = 'Microsoft.Graph.Identity.DirectoryManagement'
            ModuleVersion = '2.6.1'
        }, @{
            Guid          = '71150504-37a3-48c6-82c7-7a00a12168db'
            ModuleName    = 'Microsoft.Graph.Users'
            ModuleVersion = '2.6.1'
        }, @{
            Guid          = '60f889fa-f873-43ad-b7d3-b7fc1273a44f'
            ModuleName    = 'Microsoft.Graph.Identity.SignIns'
            ModuleVersion = '2.6.1'
        }, @{
            Guid          = '530fc574-049c-42cc-810e-8835853204b7'
            ModuleName    = 'Microsoft.Graph.Identity.Governance'
            ModuleVersion = '2.6.1'
        }, @{
            Guid          = '60dd4136-feff-401a-ba27-a84458c57ede'
            ModuleName    = 'ImportExcel'
            ModuleVersion = '7.8.6'
        }, @{
            Guid          = 'c765c957-c730-4520-9c36-6a522e35d60b'
            ModuleName    = 'MSAL.PS'
            ModuleVersion = '4.37.0.0'
        }, @{
            Guid          = 'd60c0004-962d-4dfb-8d28-5707572ffd00'
            ModuleName    = 'AzureAD'
            ModuleVersion = '2.0.2.182'
        }, 'Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Archive', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management')
    RootModule           = 'DCToolbox.psm1'
}