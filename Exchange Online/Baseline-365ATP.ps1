<##################################################################################################
#
.SYNOPSIS
This script configures a new tenant with Office 365 Advanced Threat Protection Plan 1.
In the future you can simply use the protection templates which will be available in the Security & Compliance center.
Until then, use this to get a good baseline configuration in place.

Connect to Exchange Online via PowerShell using MFA:
https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps

.NOTES
    FileName:    Baseline-365ATP.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     November 2019
	Revised:     August 2020
    Version:     3.1
    
#>
###################################################################################################

#################################################
## CONFIGURE OFFICE 365 ATP SETTINGS
#################################################


function Set-DefaultBaseline365ATP {
    [CmdletBinding()]
    Param 
    (
        $EnableTargetedUserProtection = $false,
        $TargetedUsersToProtect = $TargetedUsersToProtect,
        $EnableOrganizationDomainsProtection = $true,
        $EnableTargetedDomainsProtection = $false,
        $TargetedUserProtectionAction = 'Quarantine',
        $TargetedDomainProtectionAction = 'Quarantine',
        $EnableSimilarUsersSafetyTips = $true,
        $EnableSimilarDomainsSafetyTips = $true,
        $EnableUnusualCharactersSafetyTips = $true,
        $EnableMailboxIntelligence = $true,
        $EnableMailboxIntelligenceProtection = $true,
        $MailboxIntelligenceProtectionAction = 'MoveToJmf',
        #$EnableAntispoofEnforcement = $true,
        $EnableUnauthenticatedSender = $true,
        $AuthenticationFailAction = 'MoveToJmf',
        $PhishThresholdLevel = 2,
        $Enabled = $true
    )
}

<#
$AcceptedDomains = Get-AcceptedDomain
$RecipientDomains = $AcceptedDomains.DomainName

Write-Host 
Write-Host -foregroundcolor green "Creating the Anti-Phish Baseline Policy..."

## Create the Anti-Phish policy 
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-antiphishpolicy?view=exchange-ps
## You can edit the below to enable TargetedDomainsToProtect as well as TargetedUsersToProtect, as needed (optional).

Connect-ExchangeOnline
Connect-MsolService

$AcceptedDomains = Get-AcceptedDomain
$RecipientDomains = $AcceptedDomains.DomainName

$upn = get-msoluser | select DisplayName, UserPrincipalName
$TargetedUsersToProtect = foreach ($n in $upn) { $n.DisplayName, $n.UserPrincipalName -join ";" };


$TargetedUsersToProtect

Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" @PhishPolicyParam
#>