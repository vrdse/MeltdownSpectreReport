# MeltdownSpectreReport
Query mitigation status of Meltdown and Spectre against one or multiple Windows computers. It uses parallelization for fast data collection.

The script includes [Get-SpeculationControlSettings](https://www.powershellgallery.com/packages/SpeculationControl/1.0.1/Content/SpeculationControl.psm1) from Microsoft and [Invoke-Parallel](https://github.com/RamblingCookieMonster/Invoke-Parallel) from [RamblingCookieMonster](https://github.com/RamblingCookieMonster). All credits for these functions go to them. Thank you!

# Example
## Execution against local computer

    PS C:\> .\MeltdownSpectreReport.ps1
    Speculation control settings for CVE-2017-5715 [branch target injection]

    Hardware support for branch target injection mitigation is present: False
    Windows OS support for branch target injection mitigation is present: True
    Windows OS support for branch target injection mitigation is enabled: False
    Windows OS support for branch target injection mitigation is disabled by system policy: False
    Windows OS support for branch target injection mitigation is disabled by absence of hardware support: True

    Speculation control settings for CVE-2017-5754 [rogue data cache load]

    Hardware requires kernel VA shadowing: True
    Windows OS support for kernel VA shadow is present: True
    Windows OS support for kernel VA shadow is enabled: True
    Windows OS support for PCID optimization is enabled: True

    Suggested actions

    * Install BIOS/firmware update provided by your device OEM that enables hardware support for the branch target injection mitigation.
    * Follow the guidance for enabling Windows support for speculation control mitigations are described in https://support.microsoft.com/help/4072698


    ComputerName                   : Computer01
    Manufacturer                   : HP
    Model                          : HP Spectre x360 Convertible
    BIOS                           : F.47
    CPU                            : Intel(R) Core(TM) i7-6560U CPU @ 2.20GHz
    OperatingSystem                : Microsoft Windows 10 Pro
    OSReleaseId                    : 1709
    isHyperV                       : True
    isTerminalServer               : False
    BTIHardwarePresent             : False
    BTIWindowsSupportPresent       : True
    BTIWindowsSupportEnabled       : False
    BTIDisabledBySystemPolicy      : False
    BTIDisabledByNoHardwareSupport : True
    KVAShadowRequired              : True
    KVAShadowWindowsSupportPresent : True
    KVAShadowWindowsSupportEnabled : True
    KVAShadowPcidEnabled           : True
    OSMitigationEnabled            : True
    AVCompatibility                : True
    ChromeVersion                  : 63.0.3239.132
    ChromeSitePerProcess           : False
    InstalledUpdates               : {@{HotFixId=KB4048951; Description=Security Update; InstalledOn=15.11.2017 00:00:00; ComputerName=Computer01},
                                    @{HotFixId=KB4049179; Description=Security Update; InstalledOn=05.11.2017 00:00:00; ComputerName=Computer01},
                                    @{HotFixId=KB4051613; Description=Update; InstalledOn=09.11.2017 00:00:00; ComputerName=Computer01}, @{HotFixId=KB4053577;
                                    Description=Security Update; InstalledOn=01.01.2018 00:00:00; ComputerName=Computer01}...}
    LastReboot                     : 05.01.2018 11:28:31
    ExecutionDate                  : 05.01.2018

## Execution against multiple computers
```powershell
    PS C:\> $ComputerName = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
        $Report = .\MeltdownSpectreReport.ps1 -ComputerName $ComputerName
        $Report | ConvertTo-Csv -NoTypeInformation -Delimiter ',' | Out-File C:\report.csv
        $Report | Out-GridView
```

# Properties
## isHyperV
Is `true` if `vmms` Service is running. Hypervisors are at increased risk.
## isTerminalServer
Is `true` if `TerminalServerMode` is `1`. Terminal Servers (Remote Desktop Servers) are at increased risk.
## BTI
BTI is *Branch Target Injection* as described in [CVE-2017-5715](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5715) alias [Spectre](https://spectreattack.com/).

`BTIHardwarePresent` is `true` if the Hardware supports a mitigation. Check for BIOS/firmware updates provided by your device OEM.

`BTIWindowsSupportPresent` is `true` if the required Windows security update is installed. 

`BTIWindowsSupportEnabled` is `true` the Branch Target Injection mitigation is effective.

## KVA
KVA checks OS mitigation against [CVE-2017-5754](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5754) alias [Meltdown](https://meltdownattack.com/).

## OSMitigationEnabled
As per [Windows Server guidance to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/help/4072698
):

> Customers need to enable mitigations to help protect against speculative execution side-channel vulnerabilities.
> 
> Enabling these mitigations may affect performance. The actual performance impact will depend on multiple factors, such as the specific chipset in your physical host and the workloads that are running. Microsoft recommends that customers assess the performance impact for their environment and make necessary adjustments.

`OSMitigationEnabled` is `true` if the values for the registry key `Memory Management` are set as required, i.e. `FeatureSettingsOverride` is `0` and `FeatureSettingsOverrideMask` is `3`.

To create the required values, you can use the following PowerShell commands:
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -PropertyType 'DWORD' -Value '0'  -Name 'FeatureSettingsOverride'
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -PropertyType 'DWORD' -Value '3'  -Name 'FeatureSettingsOverrideMask'
```

## AVCompatibility
As per [Important information regarding the Windows security updates released on January 3, 2018 and anti-virus software](https://support.microsoft.com/help/4072699), the security updates are only installed, if the registry value `cadca5fe-87d3-4b96-b7fb-a231484277cc` is present in `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat`. 

The value is either set by the the installed Anti-Virus, or must be set manually if no Anti-Virus is installed.

To add the value manually, you can use the following line of PowerShell:
```powershell
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat' -Name 'cadca5fe-87d3-4b96-b7fb-a231484277cc' -PropertyType DWord -Value '0x00000000'
```
*Note: Only use this command, if you don't have any Anti-Virus installed, or verified that it's compatible!*

## Chrome
`ChromeVersion` is the file version of `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`. 

As per [Google’s Mitigations Against CPU Speculative Execution Attack Methods](https://support.google.com/faqs/answer/7622138) it is possible to enable [Site Isolation](https://www.chromium.org/Home/chromium-security/site-isolation) in Chrome version 63, to, at least, partly mitigate the issue. 

Earlier versions do not have a mitigation implemented.

For Chrome 64 further mitigations are announced. 

`ChromeSitePerProcess` is `true` if `HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome\SitePerProcess` is `1`. See also [Policy List/SitePerProcess](https://www.chromium.org/administrators/policy-list-3#SitePerProcess).
