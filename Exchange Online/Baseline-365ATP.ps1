function Set-DefaultBaseline365ATP {
    <#
        .SYNOPSIS
            This script configures a new tenant with Office 365 Advanced Threat Protection Plan 1.
            In the future you can simply use the protection templates which will be available in the Security & Compliance center.
            Until then, use this to get a good baseline configuration in place.

            Connect to Exchange Online via PowerShell using MFA:
            https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps1

        .DESCRIPTION
            
            
        .PARAMETER
            
        
        .PARAMETER 
            
            
        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Adam Gell
            GitHub:   https://github.com/AdamNSTA/Microsoft-Baselines/   
        
        .EXAMPLE
            
    #>
    [CmdletBinding()]
    Param 
    (
        [Parameter(Mandatory=$false)]$TargetedUsersToProtect, #This parameter uses the syntax: "DisplayName;EmailAddress".
        [Parameter(Mandatory=$false)]$EnableTargetedUserProtection,
        [Parameter(Mandatory=$false)]$TargetedUserProtectionAction = 'Quarantine', #Move the message to quarantine. Quarantined high confidence phishing messages are only available to admins. As of April 2020, quarantined phishing messages are available to the intended recipients.
        $EnableOrganizationDomainsProtection = $true,
        $EnableTargetedDomainsProtection = $true,
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

    $AcceptedDomains = Get-AcceptedDomain
    $RecipientDomains = $AcceptedDomains.DomainName

    $PhishPolicyParam=@{
        'EnableOrganizationDomainsProtection' = $EnableOrganizationDomainsProtection;
        'EnableTargetedDomainsProtection' = $EnableTargetedDomainsProtection
        'TargetedDomainsToProtect' = $RecipientDomains;
        'TargetedUserProtectionAction' =  $TargetedUserProtectionAction
        'TargetedDomainProtectionAction' =  $TargetedDomainProtectionAction
        'EnableSimilarUsersSafetyTips' = $EnableSimilarUsersSafetyTips;
        'EnableSimilarDomainsSafetyTips' = $EnableSimilarDomainsSafetyTips;
        'EnableUnusualCharactersSafetyTips' = $EnableUnusualCharactersSafetyTips;
        'EnableMailboxIntelligence' = $EnableMailboxIntelligence;
        'EnableMailboxIntelligenceProtection' = $EnableMailboxIntelligenceProtection;
        'MailboxIntelligenceProtectionAction' = $MailboxIntelligenceProtectionAction;
        'EnableAntispoofEnforcement' = $EnableAntispoofEnforcement;
        'EnableUnauthenticatedSender' = $EnableUnauthenticatedSender;
        'AuthenticationFailAction' =  $AuthenticationFailAction;
        'PhishThresholdLevel' = $PhishThresholdLevel;
        'Enabled' = $Enabled #>
        
     }

    if($TargetedUsersToProtect -eq $True -and $EnableTargetedUserProtection -eq $True) {
        Write-Host "The EnableTargetedUserProtection parameter specifies whether to enable user impersonation protection for a list of specified users"
        $upn = get-msoluser | Select-Object DisplayName, UserPrincipalName
        $TargetedUsersToProtect = foreach ($n in $upn) { $n.DisplayName, $n.UserPrincipalName -join ";" };

        Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -EnableTargetedUserProtection $EnableTargetedUserProtection -TargetedUsersToProtect $TargetedUsersToProtect -TargetedUserProtectionAction $TargetedUserProtectionAction @PhishPolicyParam
    }

    else {
        Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" @PhishThresholdLevel
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
#>