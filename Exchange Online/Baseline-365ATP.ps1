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
        [Parameter(Mandatory=$false)]$TargetedUsersToProtect, #This parameter uses the syntax: "DisplayName;EmailAddress".
        [Parameter(Mandatory=$false)]$EnableTargetedUserProtection,
        $EnableOrganizationDomainsProtection = $true,
        $EnableTargetedDomainsProtection = $false,
        $TargetedUserProtectionAction = 'Quarantine', #Move the message to quarantine. Quarantined high confidence phishing messages are only available to admins. As of April 2020, quarantined phishing messages are available to the intended recipients.
        $TargetedDomainProtectionAction = 'Quarantine', #Move the message to quarantine. Quarantined high confidence phishing messages are only available to admins. As of April 2020, quarantined phishing messages are available to the intended recipients.
        $EnableSimilarUsersSafetyTips = $true,
        $EnableSimilarDomainsSafetyTips = $true,
        $EnableUnusualCharactersSafetyTips = $true,
        $EnableMailboxIntelligence = $true,
        $EnableMailboxIntelligenceProtection = $true,
        $MailboxIntelligenceProtectionAction = 'MoveToJmf', #Deliver the message to the recipient's mailbox, and move the message to the Junk Email folder.
        $EnableAntispoofEnforcement = $true,
        $EnableUnauthenticatedSender = $true,
        $AuthenticationFailAction = 'MoveToJmf', #Deliver the message to the recipient's mailbox, and move the message to the Junk Email folder.
        $PhishThresholdLevel = 2,
        $Enabled = $true
    )

    if($TargetedUsersToProtect -eq $True -and $EnableTargetedUserProtection -eq $True) {
        Write-Host "The EnableTargetedUserProtection parameter specifies whether to enable user impersonation protection for a list of specified users"
        $upn = get-msoluser | Select-Object DisplayName, UserPrincipalName
        $TargetedUsersToProtect = foreach ($n in $upn) { $n.DisplayName, $n.UserPrincipalName -join ";" };
        Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" 
    }

    else {
        Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" 
    }

}

<#
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

Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" @PhishPolicyParam
#>