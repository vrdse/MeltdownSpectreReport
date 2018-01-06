# MeltdownSpectreReport
Query mitigation status of Meltdown and Spectre against one or multiple Windows computers. It uses parallelization for fast data collection.

Report includes
* Mitigation status for CVE-2017-5754 in Windows
* Mitigation status for CVE-2017-5715 in Windows
* Mitigation status for CVE-2017-5753 in Edge
* Mitigation status for CVE-2017-5753 in IE
* Mitigation status for CVE-2017-5753 in Chrome
* Mitigation status for CVE-2017-5753 in Firefox
* Information to assess the risk (CPU, Hyper-V, Terminal Server, Docker)
* Information for troubleshooting (Hardware Manufacturer and Model, Registry Keys, Uptime, Installed Hotfixes, ...)

It requires `PowerShell 2.0 or later` and `PSRemoting` enabled on remote systems.

The script includes [Get-SpeculationControlSettings](https://www.powershellgallery.com/packages/SpeculationControl/1.0.2/Content/SpeculationControl.psm1) from Microsoft and [Invoke-Parallel](https://github.com/RamblingCookieMonster/Invoke-Parallel) from [RamblingCookieMonster](https://github.com/RamblingCookieMonster). All credits for these functions go to them. Thank you!

# Example
## Execution against local computer

    PS C:\> .\MeltdownSpectreReport.ps1 -ComputerName computer01
    ComputerName                       : computer01
    Manufacturer                       : HP
    Model                              : HP Spectre x360 Convertible
    BIOS                               : F.47
    CPU                                : Intel(R) Core(TM) i7-6560U CPU @ 2.20GHz
    OperatingSystem                    : Microsoft Windows 10 Pro
    OSReleaseId                        : 1709
    isHyperV                           : True
    isTerminalServer                   : False
    isDocker                           : True
    CVE-2017-5754 mitigated            : True
    CVE-2017-5715 mitigated            : False
    CVE-2017-5753 mitigated in Edge    : True
    CVE-2017-5753 mitigated in IE      : True
    CVE-2017-5753 mitigated in Chrome  : False
    CVE-2017-5753 mitigated in Firefox : True
    BTIHardwarePresent                 : False
    BTIWindowsSupportPresent           : True
    BTIWindowsSupportEnabled           : False
    BTIDisabledBySystemPolicy          : False
    BTIDisabledByNoHardwareSupport     : True
    KVAShadowRequired                  : True
    KVAShadowWindowsSupportPresent     : True
    KVAShadowWindowsSupportEnabled     : True
    KVAShadowPcidEnabled               : True
    OSMitigationRegKeySet              :
    AVCompatibility                    : True
    MinVmVersionForCpuBasedMitigations : 2.0
    InstalledUpdates                   : {@{HotFixId=KB4048951; Description=Security Update; InstalledOn=15.11.2017 00:00:00; ComputerName=computer01},
    @{HotFixId=KB4049179; Description=Security Update; InstalledOn=05.11.2017 00:00:00; ComputerName=computer01},...}
    Uptime                             : 15:01:18.3875647
    ExecutionDate                      : 06.01.2018

## Execution against multiple computers
```powershell
PS C:\> $ComputerName = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
$Report = .\MeltdownSpectreReport.ps1 -ComputerName $ComputerName
$Report | ConvertTo-Csv -NoTypeInformation -Delimiter ',' | Out-File C:\report.csv
$Report | Out-GridView
```
```powershell
PS C:\> $ComputerName = Get-Content $env:USERPROFILE\Desktop\servers.txt
.\MeltdownSpectreReport.ps1 -ComputerName $ComputerName -ErrorAction SilentlyContinue | 
Export-Csv -Path $env:USERPROFILE\Desktop\servers.txt -NoTypeInformation
```
# Properties
## Mitigation Status
This highly relies on the information from [Spectre still unfixed, unlike what Intel says](https://gist.github.com/woachk/2f86755260f2fee1baf71c90cd6533e9) and [CPU security bugs caused by speculative execution](https://github.com/marcan/speculation-bugs/blob/master/README.md). I highly recommend to read them.

*Note: Not every mitigation, especially for CVE-2017-5753, is of the same quality. As the root cause relies in the CPU, all these mitigations are not really a **fix** to the actual problem. Mitigation means, it's "more difficult to exploit", and not every mitigation makes it equally difficult. The report only knows `true` or `false` for the mitigation. `true` is usually considered as "as good mitigated as currently possible"*

### CVE-2017-5754 mitigated (aka Meltdown)
Is `true` if CVE-2017-5754 mitigated if `KVAShadowRequired` is `false`, or if `KVAShadowWindowsSupportPresent`, `KVAShadowWindowsSupportEnabled`, and `KVAShadowPcidEnabled` are `true`. The test are actually done by [Get-SpeculationControlSettings](https://www.powershellgallery.com/packages/SpeculationControl/1.0.2/Content/SpeculationControl.psm1)].

### CVE-2017-5715 mitigated (aka Spectre Variant 2)
Is `true` if `BTIHardwarePresent`, `BTIWindowsSupportPresent`, and `BTIWindowsSupportEnabled` are `true`. The test are actually done by [Get-SpeculationControlSettings](https://www.powershellgallery.com/packages/SpeculationControl/1.0.2/Content/SpeculationControl.psm1)]

### CVE-2017-5753 mitigated in Edge (aka Spectre Variant 1)
Is `true` if one of the following Windows Updates is installed:
'KB4056893', 'KB4056890', 'KB4056891', 'KB4056892', 'KB4056888'

The list of updates was obtained from [ADV180002 | Guidance to mitigate speculative execution side-channel vulnerabilities](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180002).

Is `empty` if Edge was not found.

### CVE-2017-5753 mitigated in IE (aka Spectre Variant 1)
Is `true` if one of the following Windows Updates is installed:
'KB4056890', 'KB4056895', 'KB4056894', 'KB4056568', 'KB4056893', 'KB4056891', 'KB4056892'

The list of updates was obtained from [ADV180002 | Guidance to mitigate speculative execution side-channel vulnerabilities](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180002).

Also see [Mitigating speculative execution side-channel attacks in Microsoft Edge and Internet Explorer](https://blogs.windows.com/msedgedev/2018/01/03/speculative-execution-mitigations-microsoft-edge-internet-explorer/) for details.

Is `empty` if IE was not found.

### CVE-2017-5753 mitigated in Chrome (aka Spectre Variant 1)
Is `true` if `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe` is version >=64, or 63 and `Site Isolation` is enabled by policy.

See [Google’s Mitigations Against CPU Speculative Execution Attack Methods](https://support.google.com/faqs/answer/7622138), [Actions Required to Mitigate Speculative Side-Channel Attack Techniques](https://www.chromium.org/Home/chromium-security/ssca) for details.

Read more about [Site Isolation](https://www.chromium.org/Home/chromium-security/site-isolation) and enable if desired as follows: 

`HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome\SitePerProcess` is `1`. 

See also [Policy List/SitePerProcess](https://www.chromium.org/administrators/policy-list-3#SitePerProcess).

Is `empty` if Chrome was not found.

### CVE-2017-5753 mitigated in Firefox (aka Spectre Variant 1)
Is `true` if `C:\Program Files\Mozilla Firefox\firefox.exe` or `C:\Program Files (x86)\Mozilla Firefox\firefox.exe` is version >=54.0.7

See [Mitigations landing for new class of timing attack](https://blog.mozilla.org/security/2018/01/03/mitigations-landing-new-class-timing-attack/) for details.

Is `empty` if Firefox was not found.

## Roles

### isHyperV
Is `true` if `vmms` (Hyper-V Management) Service is running. 

Hypervisors are at increased risk.

### isTerminalServer
Is `true` if `TerminalServerMode` is `1`. 

Terminal Servers (Remote Desktop Servers) are at increased risk.

### isDocker
Is `true` if `PATH` system variable contains `docker` (which is the default). 

Container hoster are at increased risk.

## SpeculationControlSettings

### BTI*
BTI is *Branch Target Injection* as described in [CVE-2017-5715](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5715) alias [Spectre](https://spectreattack.com/) (Variant 2). 

This vulnerability requires always a microcode update for the CPU, which will be offered by the hardware OEM.

These properties might give you further insights, why `CVE-2017-5715 mitigated` is `false`.

### KVA*
KVA or Kernel VA (also known as KPTI (Kernel page-table isolation) or KAISER) removes the mapping of kernel memory in user space process and thus mitigates the practical explotation of [CVE-2017-5754](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5754) alias [Meltdown](https://meltdownattack.com/).

`KVAShadowPcidEnabled`, too, needs the microcode CPU update that comes with a BIOS/firmware update by your vendor.

These properties might give you further insights, why `CVE-2017-5754 mitigated` is `false`.

## Registry Keys
### OSMitigationRegKeySet
As per [Windows Server guidance to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/help/4072698
):

> Customers need to enable mitigations to help protect against speculative execution side-channel vulnerabilities.
> 
> Enabling these mitigations may affect performance. The actual performance impact will depend on multiple factors, such as the specific chipset in your physical host and the workloads that are running. Microsoft recommends that customers assess the performance impact for their environment and make necessary adjustments.

`OSMitigationRegKeySet` is `true` if the values for the registry key `Memory Management` are set as required, i.e. `FeatureSettingsOverride` is `0` and `FeatureSettingsOverrideMask` is `3`.
`OSMitigationRegKeySet` is `empty` if the computer is a client.

To create the required values, you can use the following PowerShell commands:
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -PropertyType 'DWORD' -Value '0'  -Name 'FeatureSettingsOverride'
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -PropertyType 'DWORD' -Value '3'  -Name 'FeatureSettingsOverrideMask'
```

*Note: This is not required for Clients.*

### AVCompatibility
As per [Important information regarding the Windows security updates released on January 3, 2018 and anti-virus software](https://support.microsoft.com/help/4072699), the security updates are only installed, if the registry value `cadca5fe-87d3-4b96-b7fb-a231484277cc` is present in `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat`. 

The value is either set by the the installed Anti-Virus, or must be set manually if no Anti-Virus is installed.

To add the value manually, you can use the following line of PowerShell:
```powershell
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat' -Name 'cadca5fe-87d3-4b96-b7fb-a231484277cc' -PropertyType DWord -Value '0x00000000'
```
*Note: Only use this command, if you don't have any Anti-Virus installed, or verified that it's compatible!*

### MinVmVersionForCpuBasedMitigations
If Hyper-V is installed, an additional Registry value has to be taken care of.
`MinVmVersionForCpuBasedMitigations` is the value of the minimum supported VM version for CVE-2017-5715 fix of VM guests. If Hyper-V is not active, it's `empty`.

From [Protecting guest virtual machines from CVE-2017-5715 (branch target injection)](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/CVE-2017-5715-and-hyper-v-vms)
> By default, virtual machines with a VM version below 8.0 will not have access to updated firmware capabilities required to mitigate CVE-2017-5715. Because VM version 8.0 is only available starting with Windows Server 2016, users of Windows Server 2012 R2 or earlier must modify a specific registry value on all machines in their cluster.

To give every VM version access to the updated firmware capabilities, you can use the following PowerShell code:

```powershell
if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization' -ErrorAction SilentlyContinue).MinVmVersionForCpuBasedMitigations) {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization' -Name MinVmVersionForCpuBasedMitigations -Value '1.0'
}
else {
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization' -Name MinVmVersionForCpuBasedMitigations -PropertyType String -Value '1.0'
}
```

*Note: A cold reboot of each VM is required. Rebooting the OS from inside the Guest is not sufficient to make the setting effective. You have to Turn the machine off and on again.

This can be considered as the Hyper-V Guest equivalent to "microcode CPU update from hardware OEM".

# History
### 0.4.2
* \* issue with 'CVE-2017-5753 mitigated in IE' and PSv2 fixed
### 0.4.1
* \* fixing "Firefox.exe located in Program Files (x86) #1"
### 0.4
* \+ MinVmVersionForCpuBasedMitigations added
### 0.3.1
* \* OSMitigationRegKeySet fix
### 0.3
* \+ CVE properties added
* \+ CVE-2017-5753 for Edge, IE, Chrome, and Firefox
* \+ isDocker check
* \+ Get-SpeculationControlSettings updated to 1.0.2
### 0.2
* \+ PowerShellv2 support