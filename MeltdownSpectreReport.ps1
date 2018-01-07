<#
.SYNOPSIS
    Query mitigation status of Meltdown and Spectre against one or multiple computers
.DESCRIPTION
    This script uses Get-SpeculationControlSettings (Microsoft) to get the mitigation status for Windows, 
    and extends the information with various registry keys, computer and software information to get a 
    broader picture. Also it uses Invoke-Parallel (RamblingCookieMonster) and Invoke-Command to obtain the 
    information from remote computers with speed.
.EXAMPLE
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
                                        @{HotFixId=KB4049179; Description=Security Update; InstalledOn=05.11.2017 00:00:00; ComputerName=computer01},
                                        @{HotFixId=KB4051613; Description=Update; InstalledOn=09.11.2017 00:00:00; ComputerName=computer01}, @{HotFixId=KB4053577;
                                        Description=Security Update; InstalledOn=01.01.2018 00:00:00; ComputerName=computer01}...}
    Uptime                             : 15:01:18.3875647
    ExecutionDate                      : 06.01.2018
.EXAMPLE
    PS C:\> $ComputerName = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
    $Report = .\MeltdownSpectreReport.ps1 -ComputerName $ComputerName
    $Report | ConvertTo-Csv -NoTypeInformation -Delimiter ',' | Out-File C:\report.csv
    $Report | Out-GridView
.EXAMPLE
    PS C:\> $ComputerName = Get-Content $env:USERPROFILE\Desktop\servers.txt
    .\MeltdownSpectreReport.ps1 -ComputerName $ComputerName -ErrorAction SilentlyContinue | 
    Export-Csv -Path $env:USERPROFILE\Desktop\servers.txt -NoTypeInformation
.NOTES
    Author: VRDSE
    Version: 0.4.3
#>
[CmdletBinding()]
param(
    # Specify remote computers to query against. If not set, local computer is queried.
    [Parameter()]
    [string[]]
    $ComputerName
)
function Invoke-Parallel {
    <#
    .SYNOPSIS
        Function to control parallel processing using runspaces

    .DESCRIPTION
        Function to control parallel processing using runspaces

            Note that each runspace will not have access to variables and commands loaded in your session or in other runspaces by default.
            This behaviour can be changed with parameters.

    .PARAMETER ScriptFile
        File to run against all input objects.  Must include parameter to take in the input object, or use $args.  Optionally, include parameter to take in parameter.  Example: C:\script.ps1

    .PARAMETER ScriptBlock
        Scriptblock to run against all computers.

        You may use $Using:<Variable> language in PowerShell 3 and later.

            The parameter block is added for you, allowing behaviour similar to foreach-object:
                Refer to the input object as $_.
                Refer to the parameter parameter as $parameter

    .PARAMETER InputObject
        Run script against these specified objects.

    .PARAMETER Parameter
        This object is passed to every script block.  You can use it to pass information to the script block; for example, the path to a logging folder

            Reference this object as $parameter if using the scriptblock parameterset.

    .PARAMETER ImportVariables
        If specified, get user session variables and add them to the initial session state

    .PARAMETER ImportModules
        If specified, get loaded modules and pssnapins, add them to the initial session state

    .PARAMETER Throttle
        Maximum number of threads to run at a single time.

    .PARAMETER SleepTimer
        Milliseconds to sleep after checking for completed runspaces and in a few other spots.  I would not recommend dropping below 200 or increasing above 500

    .PARAMETER RunspaceTimeout
        Maximum time in seconds a single thread can run.  If execution of your code takes longer than this, it is disposed.  Default: 0 (seconds)

        WARNING:  Using this parameter requires that maxQueue be set to throttle (it will be by default) for accurate timing.  Details here:
        http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430

    .PARAMETER NoCloseOnTimeout
        Do not dispose of timed out tasks or attempt to close the runspace if threads have timed out. This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.

    .PARAMETER MaxQueue
        Maximum number of powershell instances to add to runspace pool.  If this is higher than $throttle, $timeout will be inaccurate

        If this is equal or less than throttle, there will be a performance impact

        The default value is $throttle times 3, if $runspaceTimeout is not specified
        The default value is $throttle, if $runspaceTimeout is specified

    .PARAMETER LogFile
        Path to a file where we can log results, including run time for each thread, whether it completes, completes with errors, or times out.

    .PARAMETER AppendLog
        Append to existing log

    .PARAMETER Quiet
        Disable progress bar

    .EXAMPLE
        Each example uses Test-ForPacs.ps1 which includes the following code:
            param($computer)

            if(test-connection $computer -count 1 -quiet -BufferSize 16){
                $object = [pscustomobject] @{
                    Computer=$computer;
                    Available=1;
                    Kodak=$(
                        if((test-path "\\$computer\c$\users\public\desktop\Kodak Direct View Pacs.url") -or (test-path "\\$computer\c$\documents and settings\all users\desktop\Kodak Direct View Pacs.url") ){"1"}else{"0"}
                    )
                }
            }
            else{
                $object = [pscustomobject] @{
                    Computer=$computer;
                    Available=0;
                    Kodak="NA"
                }
            }

            $object

    .EXAMPLE
        Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject $(get-content C:\pcs.txt) -runspaceTimeout 10 -throttle 10

            Pulls list of PCs from C:\pcs.txt,
            Runs Test-ForPacs against each
            If any query takes longer than 10 seconds, it is disposed
            Only run 10 threads at a time

    .EXAMPLE
        Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject c-is-ts-91, c-is-ts-95

            Runs against c-is-ts-91, c-is-ts-95 (-computername)
            Runs Test-ForPacs against each

    .EXAMPLE
        $stuff = [pscustomobject] @{
            ContentFile = "windows\system32\drivers\etc\hosts"
            Logfile = "C:\temp\log.txt"
        }

        $computers | Invoke-Parallel -parameter $stuff {
            $contentFile = join-path "\\$_\c$" $parameter.contentfile
            Get-Content $contentFile |
                set-content $parameter.logfile
        }

        This example uses the parameter argument.  This parameter is a single object.  To pass multiple items into the script block, we create a custom object (using a PowerShell v3 language) with properties we want to pass in.

        Inside the script block, $parameter is used to reference this parameter object.  This example sets a content file, gets content from that file, and sets it to a predefined log file.

    .EXAMPLE
        $test = 5
        1..2 | Invoke-Parallel -ImportVariables {$_ * $test}

        Add variables from the current session to the session state.  Without -ImportVariables $Test would not be accessible

    .EXAMPLE
        $test = 5
        1..2 | Invoke-Parallel {$_ * $Using:test}

        Reference a variable from the current session with the $Using:<Variable> syntax.  Requires PowerShell 3 or later. Note that -ImportVariables parameter is no longer necessary.

    .FUNCTIONALITY
        PowerShell Language

    .NOTES
        Credit to Boe Prox for the base runspace code and $Using implementation
            http://learn-powershell.net/2012/05/10/speedy-network-information-query-using-powershell/
            http://gallery.technet.microsoft.com/scriptcenter/Speedy-Network-Information-5b1406fb#content
            https://github.com/proxb/PoshRSJob/

        Credit to T Bryce Yehl for the Quiet and NoCloseOnTimeout implementations

        Credit to Sergei Vorobev for the many ideas and contributions that have improved functionality, reliability, and ease of use

    .LINK
        https://github.com/RamblingCookieMonster/Invoke-Parallel
    #>
    [cmdletbinding(DefaultParameterSetName = 'ScriptBlock')]
    Param (
        [Parameter(Mandatory = $false, position = 0, ParameterSetName = 'ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false, ParameterSetName = 'ScriptFile')]
        [ValidateScript( {Test-Path $_ -pathtype leaf})]
        $ScriptFile,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Alias('CN', '__Server', 'IPAddress', 'Server', 'ComputerName')]
        [PSObject]$InputObject,

        [PSObject]$Parameter,

        [switch]$ImportVariables,
        [switch]$ImportModules,
        [switch]$ImportFunctions,

        [int]$Throttle = 20,
        [int]$SleepTimer = 200,
        [int]$RunspaceTimeout = 0,
        [switch]$NoCloseOnTimeout = $false,
        [int]$MaxQueue,

        [validatescript( {Test-Path (Split-Path $_ -parent)})]
        [switch] $AppendLog = $false,
        [string]$LogFile,

        [switch] $Quiet = $false
    )
    begin {
        #No max queue specified?  Estimate one.
        #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
        if ( -not $PSBoundParameters.ContainsKey('MaxQueue') ) {
            if ($RunspaceTimeout -ne 0) { $script:MaxQueue = $Throttle }
            else { $script:MaxQueue = $Throttle * 3 }
        }
        else {
            $script:MaxQueue = $MaxQueue
        }
        Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

        #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
        if ($ImportVariables -or $ImportModules -or $ImportFunctions) {
            $StandardUserEnv = [powershell]::Create().addscript( {

                    #Get modules, snapins, functions in this clean runspace
                    $Modules = Get-Module | Select-Object -ExpandProperty Name
                    $Snapins = Get-PSSnapin | Select-Object -ExpandProperty Name
                    $Functions = Get-ChildItem function:\ | Select-Object -ExpandProperty Name

                    #Get variables in this clean runspace
                    #Called last to get vars like $? into session
                    $Variables = Get-Variable | Select-Object -ExpandProperty Name

                    #Return a hashtable where we can access each.
                    @{
                        Variables = $Variables
                        Modules   = $Modules
                        Snapins   = $Snapins
                        Functions = $Functions
                    }
                }).invoke()[0]

            if ($ImportVariables) {
                #Exclude common parameters, bound parameters, and automatic variables
                Function _temp {[cmdletbinding(SupportsShouldProcess = $True)] param() }
                $VariablesToExclude = @( (Get-Command _temp | Select-Object -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                Write-Verbose "Excluding variables $( ($VariablesToExclude | Sort-Object ) -join ", ")"

                # we don't use 'Get-Variable -Exclude', because it uses regexps.
                # One of the veriables that we pass is '$?'.
                # There could be other variables with such problems.
                # Scope 2 required if we move to a real module
                $UserVariables = @( Get-Variable | Where-Object { -not ($VariablesToExclude -contains $_.Name) } )
                Write-Verbose "Found variables to import: $( ($UserVariables | Select-Object -expandproperty Name | Sort-Object ) -join ", " | Out-String).`n"
            }
            if ($ImportModules) {
                $UserModules = @( Get-Module | Where-Object {$StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path $_.Path -ErrorAction SilentlyContinue)} | Select-Object -ExpandProperty Path )
                $UserSnapins = @( Get-PSSnapin | Select-Object -ExpandProperty Name | Where-Object {$StandardUserEnv.Snapins -notcontains $_ } )
            }
            if ($ImportFunctions) {
                $UserFunctions = @( Get-ChildItem function:\ | Where-Object { $StandardUserEnv.Functions -notcontains $_.Name } )
            }
        }

        #region functions
        Function Get-RunspaceData {
            [cmdletbinding()]
            param( [switch]$Wait )
            #loop through runspaces
            #if $wait is specified, keep looping until all complete
            Do {
                #set more to false for tracking completion
                $more = $false

                #Progress bar if we have inputobject count (bound parameter)
                if (-not $Quiet) {
                    Write-Progress  -Activity "Running Query" -Status "Starting threads"`
                        -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
                        -PercentComplete $( Try { $script:completedCount / $totalCount * 100 } Catch {0} )
                }

                #run through each runspace.
                Foreach ($runspace in $runspaces) {

                    #get the duration - inaccurate
                    $currentdate = Get-Date
                    $runtime = $currentdate - $runspace.startTime
                    $runMin = [math]::Round( $runtime.totalminutes , 2 )

                    #set up log object
                    $log = "" | Select-Object Date, Action, Runtime, Status, Details
                    $log.Action = "Removing:'$($runspace.object)'"
                    $log.Date = $currentdate
                    $log.Runtime = "$runMin minutes"

                    #If runspace completed, end invoke, dispose, recycle, counter++
                    If ($runspace.Runspace.isCompleted) {

                        $script:completedCount++

                        #check if there were errors
                        if ($runspace.powershell.Streams.Error.Count -gt 0) {
                            #set the logging info and move the file to completed
                            $log.status = "CompletedWithErrors"
                            Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            foreach ($ErrorRecord in $runspace.powershell.Streams.Error) {
                                Write-Error -ErrorRecord $ErrorRecord
                            }
                        }
                        else {
                            #add logging details and cleanup
                            $log.status = "Completed"
                            Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        }

                        #everything is logged, clean up the runspace
                        $runspace.powershell.EndInvoke($runspace.Runspace)
                        $runspace.powershell.dispose()
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                    }
                    #If runtime exceeds max, dispose the runspace
                    ElseIf ( $runspaceTimeout -ne 0 -and $runtime.totalseconds -gt $runspaceTimeout) {
                        $script:completedCount++
                        $timedOutTasks = $true

                        #add logging details and cleanup
                        $log.status = "TimedOut"
                        Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        Write-Error "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | out-string)"

                        #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                        if (!$noCloseOnTimeout) { $runspace.powershell.dispose() }
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                        $completedCount++
                    }

                    #If runspace isn't null set more to true
                    ElseIf ($runspace.Runspace -ne $null ) {
                        $log = $null
                        $more = $true
                    }

                    #log the results if a log file was indicated
                    if ($logFile -and $log) {
                        ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                    }
                }

                #Clean out unused runspace jobs
                $temphash = $runspaces.clone()
                $temphash | Where-Object { $_.runspace -eq $Null } | ForEach-Object {
                    $Runspaces.remove($_)
                }

                #sleep for a bit if we will loop again
                if ($PSBoundParameters['Wait']) { Start-Sleep -milliseconds $SleepTimer }

                #Loop again only if -wait parameter and there are more runspaces to process
            } while ($more -and $PSBoundParameters['Wait'])

            #End of runspace function
        }
        #endregion functions

        #region Init

        if ($PSCmdlet.ParameterSetName -eq 'ScriptFile') {
            $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | out-string) )
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'ScriptBlock') {
            #Start building parameter names for the param block
            [string[]]$ParamsToAdd = '$_'
            if ( $PSBoundParameters.ContainsKey('Parameter') ) {
                $ParamsToAdd += '$Parameter'
            }

            $UsingVariableData = $Null

            # This code enables $Using support through the AST.
            # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!

            if ($PSVersionTable.PSVersion.Major -gt 2) {
                #Extract using references
                $UsingVariables = $ScriptBlock.ast.FindAll( {$args[0] -is [System.Management.Automation.Language.UsingExpressionAst]}, $True)

                If ($UsingVariables) {
                    $List = New-Object 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                    ForEach ($Ast in $UsingVariables) {
                        [void]$list.Add($Ast.SubExpression)
                    }

                    $UsingVar = $UsingVariables | Group-Object -Property SubExpression | ForEach-Object {$_.Group | Select-Object -First 1}

                    #Extract the name, value, and create replacements for each
                    $UsingVariableData = ForEach ($Var in $UsingVar) {
                        try {
                            $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                            [pscustomobject]@{
                                Name       = $Var.SubExpression.Extent.Text
                                Value      = $Value.Value
                                NewName    = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                            }
                        }
                        catch {
                            Write-Error "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                        }
                    }
                    $ParamsToAdd += $UsingVariableData | Select-Object -ExpandProperty NewName -Unique

                    $NewParams = $UsingVariableData.NewName -join ', '
                    $Tuple = [Tuple]::Create($list, $NewParams)
                    $bindingFlags = [Reflection.BindingFlags]"Default,NonPublic,Instance"
                    $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl', $bindingFlags))

                    $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast, @($Tuple))

                    $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                    Write-Verbose $StringScriptBlock
                }
            }

            $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ", "))`r`n" + $Scriptblock.ToString())
        }
        else {
            Throw "Must provide ScriptBlock or ScriptFile"; Break
        }

        Write-Debug "`$ScriptBlock: $($ScriptBlock | Out-String)"
        Write-Verbose "Creating runspace pool and session states"

        #If specified, add variables and modules/snapins to session state
        $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        if ($ImportVariables -and $UserVariables.count -gt 0) {
            foreach ($Variable in $UserVariables) {
                $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
            }
        }
        if ($ImportModules) {
            if ($UserModules.count -gt 0) {
                foreach ($ModulePath in $UserModules) {
                    $sessionstate.ImportPSModule($ModulePath)
                }
            }
            if ($UserSnapins.count -gt 0) {
                foreach ($PSSnapin in $UserSnapins) {
                    [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                }
            }
        }
        if ($ImportFunctions -and $UserFunctions.count -gt 0) {
            foreach ($FunctionDef in $UserFunctions) {
                $sessionstate.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $FunctionDef.Name, $FunctionDef.ScriptBlock))
            }
        }

        #Create runspace pool
        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
        $runspacepool.Open()

        Write-Verbose "Creating empty collection to hold runspace jobs"
        $Script:runspaces = New-Object System.Collections.ArrayList

        #If inputObject is bound get a total count and set bound to true
        $bound = $PSBoundParameters.keys -contains "InputObject"
        if (-not $bound) {
            [System.Collections.ArrayList]$allObjects = @()
        }

        #Set up log file if specified
        if ( $LogFile -and (-not (Test-Path $LogFile) -or $AppendLog -eq $false)) {
            New-Item -ItemType file -Path $logFile -Force | Out-Null
            ("" | Select-Object -Property Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
        }

        #write initial log entry
        $log = "" | Select-Object -Property Date, Action, Runtime, Status, Details
        $log.Date = Get-Date
        $log.Action = "Batch processing started"
        $log.Runtime = $null
        $log.Status = "Started"
        $log.Details = $null
        if ($logFile) {
            ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
        }
        $timedOutTasks = $false
        #endregion INIT
    }
    process {
        #add piped objects to all objects or set all objects to bound input object parameter
        if ($bound) {
            $allObjects = $InputObject
        }
        else {
            [void]$allObjects.add( $InputObject )
        }
    }
    end {
        #Use Try/Finally to catch Ctrl+C and clean up.
        try {
            #counts for progress
            $totalCount = $allObjects.count
            $script:completedCount = 0
            $startedCount = 0
            foreach ($object in $allObjects) {
                #region add scripts to runspace pool
                #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                $powershell = [powershell]::Create()

                if ($VerbosePreference -eq 'Continue') {
                    [void]$PowerShell.AddScript( {$VerbosePreference = 'Continue'})
                }

                [void]$PowerShell.AddScript($ScriptBlock).AddArgument($object)

                if ($parameter) {
                    [void]$PowerShell.AddArgument($parameter)
                }

                # $Using support from Boe Prox
                if ($UsingVariableData) {
                    Foreach ($UsingVariable in $UsingVariableData) {
                        Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                        [void]$PowerShell.AddArgument($UsingVariable.Value)
                    }
                }

                #Add the runspace into the powershell instance
                $powershell.RunspacePool = $runspacepool

                #Create a temporary collection for each runspace
                $temp = "" | Select-Object PowerShell, StartTime, object, Runspace
                $temp.PowerShell = $powershell
                $temp.StartTime = Get-Date
                $temp.object = $object

                #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                $temp.Runspace = $powershell.BeginInvoke()
                $startedCount++

                #Add the temp tracking info to $runspaces collection
                Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                $runspaces.Add($temp) | Out-Null

                #loop through existing runspaces one time
                Get-RunspaceData

                #If we have more running than max queue (used to control timeout accuracy)
                #Script scope resolves odd PowerShell 2 issue
                $firstRun = $true
                while ($runspaces.count -ge $Script:MaxQueue) {
                    #give verbose output
                    if ($firstRun) {
                        Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                    }
                    $firstRun = $false

                    #run get-runspace data and sleep for a short while
                    Get-RunspaceData
                    Start-Sleep -Milliseconds $sleepTimer
                }
                #endregion add scripts to runspace pool
            }
            Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where-Object {$_.Runspace -ne $Null}).Count) )

            Get-RunspaceData -wait
            if (-not $quiet) {
                Write-Progress -Activity "Running Query" -Status "Starting threads" -Completed
            }
        }
        finally {
            #Close the runspace pool, unless we specified no close on timeout and something timed out
            if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($noCloseOnTimeout -eq $false) ) ) {
                Write-Verbose "Closing the runspace pool"
                $runspacepool.close()
            }
            #collect garbage
            [gc]::Collect()
        }
    }
}

$GetMeltdownStatusInformation = {
    # Based on https://www.powershellgallery.com/packages/SpeculationControl/1.0.2
    function Get-SpeculationControlSettings {
        <# 
 
  .SYNOPSIS 
  This function queries the speculation control settings for the system. 
 
  .DESCRIPTION 
  This function queries the speculation control settings for the system. 
 
  Version 1.3. 
   
  #>

        [CmdletBinding()]
        param (

        )
  
        process {

            $NtQSIDefinition = @' 
    [DllImport("ntdll.dll")] 
    public static extern int NtQuerySystemInformation(uint systemInformationClass, IntPtr systemInformation, uint systemInformationLength, IntPtr returnLength); 
'@
    
            $ntdll = Add-Type -MemberDefinition $NtQSIDefinition -Name 'ntdll' -Namespace 'Win32' -PassThru


            [System.IntPtr]$systemInformationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
            [System.IntPtr]$returnLengthPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)

            $object = New-Object -TypeName PSObject

            try {
    
                #
                # Query branch target injection information.
                #

                #Write-Host "Speculation control settings for CVE-2017-5715 [branch target injection]" -ForegroundColor Cyan
                #Write-Host

                $btiHardwarePresent = $false
                $btiWindowsSupportPresent = $false
                $btiWindowsSupportEnabled = $false
                $btiDisabledBySystemPolicy = $false
                $btiDisabledByNoHardwareSupport = $false
    
                [System.UInt32]$systemInformationClass = 201
                [System.UInt32]$systemInformationLength = 4

                $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

                if ($retval -eq 0xc0000003 -or $retval -eq 0xc0000002) {
                    # fallthrough
                }
                elseif ($retval -ne 0) {
                    throw (("Querying branch target injection information failed with error {0:X8}" -f $retval))
                }
                else {
    
                    [System.UInt32]$scfBpbEnabled = 0x01
                    [System.UInt32]$scfBpbDisabledSystemPolicy = 0x02
                    [System.UInt32]$scfBpbDisabledNoHardwareSupport = 0x04
                    [System.UInt32]$scfHwReg1Enumerated = 0x08
                    [System.UInt32]$scfHwReg2Enumerated = 0x10
                    [System.UInt32]$scfHwMode1Present = 0x20
                    [System.UInt32]$scfHwMode2Present = 0x40
                    [System.UInt32]$scfSmepPresent = 0x80

                    [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)

                    $btiHardwarePresent = ((($flags -band $scfHwReg1Enumerated) -ne 0) -or (($flags -band $scfHwReg2Enumerated)))
                    $btiWindowsSupportPresent = $true
                    $btiWindowsSupportEnabled = (($flags -band $scfBpbEnabled) -ne 0)

                    if ($btiWindowsSupportEnabled -eq $false) {
                        $btiDisabledBySystemPolicy = (($flags -band $scfBpbDisabledSystemPolicy) -ne 0)
                        $btiDisabledByNoHardwareSupport = (($flags -band $scfBpbDisabledNoHardwareSupport) -ne 0)
                    }

                    if ($PSBoundParameters['Verbose']) {
                        #Write-Host "BpbEnabled :" (($flags -band $scfBpbEnabled) -ne 0)
                        #Write-Host "BpbDisabledSystemPolicy :" (($flags -band $scfBpbDisabledSystemPolicy) -ne 0)
                        #Write-Host "BpbDisabledNoHardwareSupport :" (($flags -band $scfBpbDisabledNoHardwareSupport) -ne 0)
                        #Write-Host "HwReg1Enumerated :" (($flags -band $scfHwReg1Enumerated) -ne 0)
                        #Write-Host "HwReg2Enumerated :" (($flags -band $scfHwReg2Enumerated) -ne 0)
                        #Write-Host "HwMode1Present :" (($flags -band $scfHwMode1Present) -ne 0)
                        #Write-Host "HwMode2Present :" (($flags -band $scfHwMode2Present) -ne 0)
                        #Write-Host "SmepPresent :" (($flags -band $scfSmepPresent) -ne 0)
                    }
                }

                #Write-Host "Hardware support for branch target injection mitigation is present:"($btiHardwarePresent) -ForegroundColor $(If ($btiHardwarePresent) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })
                #Write-Host "Windows OS support for branch target injection mitigation is present:"($btiWindowsSupportPresent) -ForegroundColor $(If ($btiWindowsSupportPresent) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })
                #Write-Host "Windows OS support for branch target injection mitigation is enabled:"($btiWindowsSupportEnabled) -ForegroundColor $(If ($btiWindowsSupportEnabled) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })
  
                if ($btiWindowsSupportPresent -eq $true -and $btiWindowsSupportEnabled -eq $false) {
                    #Write-Host -ForegroundColor Red "Windows OS support for branch target injection mitigation is disabled by system policy:"($btiDisabledBySystemPolicy)
                    #Write-Host -ForegroundColor Red "Windows OS support for branch target injection mitigation is disabled by absence of hardware support:"($btiDisabledByNoHardwareSupport)
                }
        
                $object | Add-Member -MemberType NoteProperty -Name BTIHardwarePresent -Value $btiHardwarePresent
                $object | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportPresent -Value $btiWindowsSupportPresent
                $object | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportEnabled -Value $btiWindowsSupportEnabled
                $object | Add-Member -MemberType NoteProperty -Name BTIDisabledBySystemPolicy -Value $btiDisabledBySystemPolicy
                $object | Add-Member -MemberType NoteProperty -Name BTIDisabledByNoHardwareSupport -Value $btiDisabledByNoHardwareSupport

                #
                # Query kernel VA shadow information.
                #

                #Write-Host
                #Write-Host "Speculation control settings for CVE-2017-5754 [rogue data cache load]" -ForegroundColor Cyan
                #Write-Host    

                $kvaShadowRequired = $true
                $kvaShadowPresent = $false
                $kvaShadowEnabled = $false
                $kvaShadowPcidEnabled = $false

                $cpu = Get-WmiObject -Class Win32_Processor | Select-Object -First 1 #Fix for the case of multiple objects returned

                if ($cpu.Manufacturer -eq "AuthenticAMD") {
                    $kvaShadowRequired = $false
                }
                elseif ($cpu.Manufacturer -eq "GenuineIntel") {
                    $regex = [regex]'Family (\d+) Model (\d+) Stepping (\d+)'
                    $result = $regex.Match($cpu.Description)
            
                    if ($result.Success) {
                        $family = [System.UInt32]$result.Groups[1].Value
                        $model = [System.UInt32]$result.Groups[2].Value
                        $stepping = [System.UInt32]$result.Groups[3].Value
                
                        if (($family -eq 0x6) -and 
                            (($model -eq 0x1c) -or
                                ($model -eq 0x26) -or
                                ($model -eq 0x27) -or
                                ($model -eq 0x36) -or
                                ($model -eq 0x35))) {

                            $kvaShadowRequired = $false
                        }
                    }
                }
                else {
                    throw ("Unsupported processor manufacturer: {0}" -f $cpu.Manufacturer)
                }

                [System.UInt32]$systemInformationClass = 196
                [System.UInt32]$systemInformationLength = 4

                $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

                if ($retval -eq 0xc0000003 -or $retval -eq 0xc0000002) {
                }
                elseif ($retval -ne 0) {
                    throw (("Querying kernel VA shadow information failed with error {0:X8}" -f $retval))
                }
                else {
    
                    [System.UInt32]$kvaShadowEnabledFlag = 0x01
                    [System.UInt32]$kvaShadowUserGlobalFlag = 0x02
                    [System.UInt32]$kvaShadowPcidFlag = 0x04
                    [System.UInt32]$kvaShadowInvpcidFlag = 0x08

                    [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)

                    $kvaShadowPresent = $true
                    $kvaShadowEnabled = (($flags -band $kvaShadowEnabledFlag) -ne 0)
                    $kvaShadowPcidEnabled = ((($flags -band $kvaShadowPcidFlag) -ne 0) -and (($flags -band $kvaShadowInvpcidFlag) -ne 0))

                    if ($PSBoundParameters['Verbose']) {
                        #Write-Host "KvaShadowEnabled :" (($flags -band $kvaShadowEnabledFlag) -ne 0)
                        #Write-Host "KvaShadowUserGlobal :" (($flags -band $kvaShadowUserGlobalFlag) -ne 0)
                        #Write-Host "KvaShadowPcid :" (($flags -band $kvaShadowPcidFlag) -ne 0)
                        #Write-Host "KvaShadowInvpcid :" (($flags -band $kvaShadowInvpcidFlag) -ne 0)
                    }
                }
        
                #Write-Host "Hardware requires kernel VA shadowing:"$kvaShadowRequired

                if ($kvaShadowRequired) {

                    #Write-Host "Windows OS support for kernel VA shadow is present:"$kvaShadowPresent -ForegroundColor $(If ($kvaShadowPresent) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })
                    #Write-Host "Windows OS support for kernel VA shadow is enabled:"$kvaShadowEnabled -ForegroundColor $(If ($kvaShadowEnabled) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })

                    if ($kvaShadowEnabled) {
                        #Write-Host "Windows OS support for PCID performance optimization is enabled: $kvaShadowPcidEnabled [not required for security]" -ForegroundColor $(If ($kvaShadowPcidEnabled) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Blue })
                    }
                }

        
                $object | Add-Member -MemberType NoteProperty -Name KVAShadowRequired -Value $kvaShadowRequired
                $object | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportPresent -Value $kvaShadowPresent
                $object | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportEnabled -Value $kvaShadowEnabled
                $object | Add-Member -MemberType NoteProperty -Name KVAShadowPcidEnabled -Value $kvaShadowPcidEnabled

                #
                # Provide guidance as appropriate.
                #

                $actions = @()
        
                if ($btiHardwarePresent -eq $false) {
                    $actions += "Install BIOS/firmware update provided by your device OEM that enables hardware support for the branch target injection mitigation."
                }

                if ($btiWindowsSupportPresent -eq $false -or $kvaShadowPresent -eq $false) {
                    $actions += "Install the latest available updates for Windows with support for speculation control mitigations."
                }

                if (($btiHardwarePresent -eq $true -and $btiWindowsSupportEnabled -eq $false) -or ($kvaShadowRequired -eq $true -and $kvaShadowEnabled -eq $false)) {
                    $guidanceUri = ""
                    $guidanceType = ""

            
                    $os = Get-WmiObject Win32_OperatingSystem

                    if ($os.ProductType -eq 1) {
                        # Workstation
                        $guidanceUri = "https://support.microsoft.com/help/4073119"
                        $guidanceType = "Client"
                    }
                    else {
                        # Server/DC
                        $guidanceUri = "https://support.microsoft.com/help/4072698"
                        $guidanceType = "Server"
                    }

                    $actions += "Follow the guidance for enabling Windows $guidanceType support for speculation control mitigations described in $guidanceUri"
                }

                if ($actions.Length -gt 0) {

                    #Write-Host
                    #Write-Host "Suggested actions" -ForegroundColor Cyan
                    #Write-Host 

                    foreach ($action in $actions) {
                        #Write-Host " *" $action
                    }
                }


                return $object

            }
            finally {
                if ($systemInformationPtr -ne [System.IntPtr]::Zero) {
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($systemInformationPtr)
                }
 
                if ($returnLengthPtr -ne [System.IntPtr]::Zero) {
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($returnLengthPtr)
                }
            }    
        }
    }    
    function Get-SystemInformation {
        $ComputerName = $env:COMPUTERNAME
        $Win32_ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $Win32_OperatingSystem = Get-WmiObject -Class Win32_OperatingSystem
        $ComputerManufacturer = $Win32_ComputerSystem.Manufacturer
        $ComputerModel = $Win32_ComputerSystem.Model
        $ProductType = $Win32_OperatingSystem.ProductType
        $BIOS = (Get-WmiObject -Class Win32_BIOS).Name
        $Processor = (Get-WmiObject -Class Win32_Processor).Name
        $OperatingSystem = $Win32_OperatingSystem.Caption
        $OSReleaseId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).ReleaseId
        $LastReboot = [Management.ManagementDateTimeConverter]::ToDateTime($Win32_OperatingSystem.LastBootUptime)
        $Uptime = ((Get-Date) - $LastReboot).ToString()
        $Hotfixes = Get-WmiObject -Class Win32_QuickFixEngineering | 
            Select-Object HotFixId, Description, InstalledOn, @{
            Name       = 'ComputerName'; 
            Expression = {$env:COMPUTERNAME}
        } | Sort-Object HotFixId
        $ExecutionDate = Get-Date -Format d

        $vmms = Get-Service -Name vmms -ErrorAction SilentlyContinue
        if ($vmms.Status -eq 'Running') {
            $isHyperV = $true
        }
        else {
            $isHyperV = $false
        }

        $TerminalServerMode = (Get-WmiObject -Namespace root\CIMV2/TerminalServices -Class Win32_TerminalServiceSetting).TerminalServerMode
        if ($TerminalServerMode -eq 1) {
            $isTerminalServer = $true
        }
        else {
            $isTerminalServer = $false
        }

        # Test for Docker
        if ($env:Path -match 'docker') {
            $isDocker = $true
        }
        else {
            $isDocker = $false
        }

        # Test for Chrome 
        # WMI Class Win32_Product does not show Chrome for me.
        # Win32_InstalledWin32Program requies administrative privileges and Windows 7
        $isChrome = Test-Path -Path 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'  

        # Test for Edge
        if ($OSReleaseId) {
            # Is Windows 10
            if (Get-AppxPackage -Name Microsoft.MicrosoftEdge) {
                $isEdge = $true
            }
            else {
                $isEdge = $false
            }
        }
        else {
            $isEdge = $false
        }

        # Test for IE
        $isIE = Test-Path -Path 'C:\Program Files\Internet Explorer\iexplore.exe'

        # Test for Firefox
        $isFirefox = (Test-Path -Path 'C:\Program Files\Mozilla Firefox\firefox.exe') -or
        (Test-Path -Path 'C:\Program Files (x86)\Mozilla Firefox\firefox.exe')

        <#
        Customers need to enable mitigations to help protect against speculative execution side-channel vulnerabilities.

        Enabling these mitigations may affect performance. The actual performance impact will depend on multiple factors such as the specific chipset in your physical host and the workloads that are running. Microsoft recommends customers assess the performance impact for their environment and make the necessary adjustments if needed.

        Your server is at increased risk if your server falls into one of the following categories:

        Hyper-V hosts
        Remote Desktop Services Hosts (RDSH)
        For physical hosts or virtual machines that are running untrusted code such as containers or untrusted extensions for database, untrusted web content or workloads that run code that is provided from external sources.
        #>
        if ($ProductType -ne 1) {
            # Product Type = Workstation
            $FeatureSettingsOverride = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -ErrorAction SilentlyContinue).FeatureSettingsOverride # must be 0
            $FeatureSettingsOverrideMask = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -ErrorAction SilentlyContinue).FeatureSettingsOverrideMask # must be 3
            if (($FeatureSettingsOverride -eq 0) -and ($FeatureSettingsOverrideMask -eq 3)) {
                $OSMitigationRegKeySet = $true
            }
            else {
                $OSMitigationRegKeySet = $false
            }
        }

        # https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/CVE-2017-5715-and-hyper-v-vms
        if ($isHyperV) {
            $MinVmVersionForCpuBasedMitigations = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization' -ErrorAction SilentlyContinue).MinVmVersionForCpuBasedMitigations
            if (-not $MinVmVersionForCpuBasedMitigations) {
                if ($OSReleaseId) {
                    $MinVmVersionForCpuBasedMitigations = '8.0'
                }
                else {
                    $MinVmVersionForCpuBasedMitigations = $false
                }
            }
        }

        <#
        Customers without Anti-Virus
        Microsoft recommends all customers protect their devices by running a supported anti-virus program. Customers can also take advantage of built-in anti-virus protection, Windows Defender for Windows 10 devices or Microsoft Security Essentials for Windows 7 devices. These solutions are compatible in cases where customers can’t install or run anti-virus software. Microsoft recommends manually setting the registry key in the following section to receive the January 2018 security updates.
        #>
        $AVRegKeyValue = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat' -ErrorAction SilentlyContinue).'cadca5fe-87d3-4b96-b7fb-a231484277cc' # must be 0
        if ($AVRegKeyValue -eq 0) {
            $AVCompatibility = $true
        }
        else {
            $AVCompatibility = $false
        }

        $output = New-Object -TypeName PSCustomObject
        $output | Add-Member -MemberType NoteProperty -Name ComputerName -Value $ComputerName
        $output | Add-Member -MemberType NoteProperty -Name Manufacturer -Value $ComputerManufacturer
        $output | Add-Member -MemberType NoteProperty -Name Model -Value $ComputerModel
        $output | Add-Member -MemberType NoteProperty -Name BIOS -Value $BIOS
        $output | Add-Member -MemberType NoteProperty -Name CPU -Value $Processor
        $output | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value $OperatingSystem
        $output | Add-Member -MemberType NoteProperty -Name ProductType -Value $ProductType
        $output | Add-Member -MemberType NoteProperty -Name OSReleaseId -Value $OSReleaseId
        $output | Add-Member -MemberType NoteProperty -Name isHyperV -Value $isHyperV
        $output | Add-Member -MemberType NoteProperty -Name isTerminalServer -Value $isTerminalServer
        $output | Add-Member -MemberType NoteProperty -Name isDocker -Value $isDocker
        $output | Add-Member -MemberType NoteProperty -Name isEdge -Value $isEdge
        $output | Add-Member -MemberType NoteProperty -Name isIE -Value $isIE
        $output | Add-Member -MemberType NoteProperty -Name isChrome -Value $isChrome
        $output | Add-Member -MemberType NoteProperty -Name isFirefox -Value $isFirefox        
        $output | Add-Member -MemberType NoteProperty -Name OSMitigationRegKeySet -Value $OSMitigationRegKeySet
        $output | Add-Member -MemberType NoteProperty -Name AVCompatibility -Value $AVCompatibility
        $output | Add-Member -MemberType NoteProperty -Name MinVmVersionForCpuBasedMitigations -Value $MinVmVersionForCpuBasedMitigations
        $output | Add-Member -MemberType NoteProperty -Name InstalledUpdates -Value $Hotfixes
        $output | Add-Member -MemberType NoteProperty -Name Uptime -Value $Uptime
        $output | Add-Member -MemberType NoteProperty -Name ExecutionDate -Value $ExecutionDate
        $output
    }

    # CVE-2017-5754 (Meltdown)
    function Get-CVE-2017-5754 ($SpeculationControlSettings, $SystemInformation) {
        if ($SpeculationControlSettings.KVAShadowRequired -eq $false) {
            $mitigated = $true
        }
        elseif (($SpeculationControlSettings.KVAShadowWindowsSupportPresent -eq $true) -and 
            ($SpeculationControlSettings.KVAShadowWindowsSupportEnabled -eq $true)) {
            $mitigated = $true
        }
        else {
            $mitigated = $false
        }
        $mitigated        
    }
    
    # CVE-2017-5715 (Spectre)
    function Get-CVE-2017-5715 ($SpeculationControlSettings, $SystemInformation) {
        # probably more -and then required, but better safe then sorry
        if (($SpeculationControlSettings.BTIHardwarePresent -eq $true) -and 
            ($SpeculationControlSettings.BTIWindowsSupportPresent -eq $true) -and
            ($SpeculationControlSettings.BTIWindowsSupportEnabled -eq $true)) {
            $mitigated = $true
        }
        else {
            $mitigated = $false
        }
        $mitigated
    }   

    # CVE-2017-5753 (Spectre)
    function Get-CVE-2017-5753 ($SystemInformation) {
        function IsHotfixInstalled ($ListOfRequiredKBs, $ListOfInstalledKBs) {
            <#
            .SYNOPSIS
                If any of the required KBs is installed, the function returns true
            #>
            foreach ($KB in $ListOfRequiredKBs) {
                if ($ListOfInstalledKBs -contains $KB) {
                    $installed = $true
                    break
                }
            }
            if ($installed) {
                $true
            }
            else {
                $false
            }
        }

        # Chrome
        # https://www.chromium.org/Home/chromium-security/site-isolation 
        if ($SystemInformation.isChrome) {
            $ChromeVersion = (Get-Item 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe').VersionInfo.ProductVersion -as [version]
            if ($ChromeVersion.Major -gt 63) {
                $ChromeMitigated = $true
            }
            elseif ($ChromeVersion.Major -eq 63) {
                $ChromeSitePerProcessSetting = (Get-ItemProperty -Path HKLM:\Software\Policies\Google\Chrome -ErrorAction SilentlyContinue).SitePerProcess # must be 1
                if ($ChromeSitePerProcessSetting -eq 1) {
                    $ChromeMitigated = $true
                }
                else {
                    $ChromeMitigated = $false
                }
            }
            else {
                $ChromeMitigated = $false
            }
        } 

        # Microsoft Browser (https://blogs.windows.com/msedgedev/2018/01/03/speculative-execution-mitigations-microsoft-edge-internet-explorer/)
        # From my understanding, the patch is effective as soon as the patch is installed

        # Edge
        if ($SystemInformation.isEdge) {
            #KBs from https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180002
            $EdgeUpdates = 'KB4056893', 'KB4056890', 'KB4056891', 'KB4056892', 'KB4056888'
            $Hotfixes = $SystemInformation.InstalledUpdates | Select-Object -ExpandProperty HotFixId
            $EdgeMitigated = IsHotfixInstalled $EdgeUpdates $Hotfixes
        } 

        # Internet Explorer 
        if ($SystemInformation.isIE) {
            # KBs from https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180002
            $IEUpdates = 'KB4056890', 'KB4056895', 'KB4056894', 'KB4056568', 'KB4056893', 'KB4056891', 'KB4056892'
            $Hotfixes = $SystemInformation.InstalledUpdates | Select-Object -ExpandProperty HotFixId
            $IEMitigated = IsHotfixInstalled $IEUpdates $Hotfixes
        } 

        # Firefox
        if ($SystemInformation.isFirefox) {
            # See https://blog.mozilla.org/security/2018/01/03/mitigations-landing-new-class-timing-attack/
            $Firefox = (Get-Item -Path 'C:\Program Files\Mozilla Firefox\firefox.exe', 
                'C:\Program Files (x86)\Mozilla Firefox\firefox.exe' -ErrorAction SilentlyContinue)
            $FirefoxVersion = ($Firefox.VersionInfo.ProductVersion | Sort-Object | Select-Object -First 1) -as [version]
            if ($FirefoxVersion -ge [version]'57.0.4') {
                $FirefoxMitigated = $true
            }
            else {
                $FirefoxMitigated = $false
            }
        }

        $output = New-Object -TypeName PSCustomObject
        $output | Add-Member -MemberType NoteProperty -Name EdgeMitigated -Value $EdgeMitigated
        $output | Add-Member -MemberType NoteProperty -Name IEMitigated -Value $IEMitigated
        $output | Add-Member -MemberType NoteProperty -Name ChromeMitigated -Value $ChromeMitigated
        $output | Add-Member -MemberType NoteProperty -Name FirefoxMitigated -Value $FirefoxMitigated
        $output
    }    

    $SystemInformation = Get-SystemInformation
    $SpeculationControlSettings = Get-SpeculationControlSettings -ErrorAction Continue
    $CVE20175754mitigated = Get-CVE-2017-5754 $SpeculationControlSettings $SystemInformation
    $CVE20175715mitigated = Get-CVE-2017-5715 $SpeculationControlSettings $SystemInformation
    $CVE20175753mitigated = Get-CVE-2017-5753 $SystemInformation

    $output = New-Object -TypeName PSCustomObject
    $output.PSObject.TypeNames.Insert(0, 'MeltdownSpectre.Report')
    $output | Add-Member -MemberType NoteProperty -Name ComputerName -Value $SystemInformation.ComputerName
    $output | Add-Member -MemberType NoteProperty -Name Manufacturer -Value $SystemInformation.Manufacturer
    $output | Add-Member -MemberType NoteProperty -Name Model -Value $SystemInformation.Model
    $output | Add-Member -MemberType NoteProperty -Name BIOS -Value $SystemInformation.BIOS
    $output | Add-Member -MemberType NoteProperty -Name CPU -Value $SystemInformation.CPU
    $output | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value $SystemInformation.OperatingSystem
    $output | Add-Member -MemberType NoteProperty -Name OSReleaseId -Value $SystemInformation.OSReleaseId
    $output | Add-Member -MemberType NoteProperty -Name isHyperV -Value $SystemInformation.isHyperV
    $output | Add-Member -MemberType NoteProperty -Name isTerminalServer -Value $SystemInformation.isTerminalServer
    $output | Add-Member -MemberType NoteProperty -Name isDocker -Value $SystemInformation.isDocker
    #$output | Add-Member -MemberType NoteProperty -Name isIE -Value $SystemInformation.isIE
    #$output | Add-Member -MemberType NoteProperty -Name isEdge -Value $SystemInformation.isEdge
    #$output | Add-Member -MemberType NoteProperty -Name isChrome -Value $SystemInformation.isChrome
    #$output | Add-Member -MemberType NoteProperty -Name isFirefox -Value $SystemInformation.isFirefox
    $output | Add-Member -MemberType NoteProperty -Name 'CVE-2017-5754 mitigated' -Value $CVE20175754mitigated
    $output | Add-Member -MemberType NoteProperty -Name 'CVE-2017-5715 mitigated' -Value $CVE20175715mitigated
    $output | Add-Member -MemberType NoteProperty -Name 'CVE-2017-5753 mitigated in Edge' -Value $CVE20175753mitigated.EdgeMitigated
    $output | Add-Member -MemberType NoteProperty -Name 'CVE-2017-5753 mitigated in IE' -Value $CVE20175753mitigated.IEMitigated
    $output | Add-Member -MemberType NoteProperty -Name 'CVE-2017-5753 mitigated in Chrome' -Value $CVE20175753mitigated.ChromeMitigated
    $output | Add-Member -MemberType NoteProperty -Name 'CVE-2017-5753 mitigated in Firefox' -Value $CVE20175753mitigated.FirefoxMitigated
    $output | Add-Member -MemberType NoteProperty -Name BTIHardwarePresent -Value $SpeculationControlSettings.BTIHardwarePresent
    $output | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportPresent -Value $SpeculationControlSettings.BTIWindowsSupportPresent
    $output | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportEnabled -Value $SpeculationControlSettings.BTIWindowsSupportEnabled
    $output | Add-Member -MemberType NoteProperty -Name BTIDisabledBySystemPolicy -Value $SpeculationControlSettings.BTIDisabledBySystemPolicy
    $output | Add-Member -MemberType NoteProperty -Name BTIDisabledByNoHardwareSupport -Value $SpeculationControlSettings.BTIDisabledByNoHardwareSupport
    $output | Add-Member -MemberType NoteProperty -Name KVAShadowRequired -Value $SpeculationControlSettings.KVAShadowRequired
    $output | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportPresent -Value $SpeculationControlSettings.KVAShadowWindowsSupportPresent
    $output | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportEnabled -Value $SpeculationControlSettings.KVAShadowWindowsSupportEnabled
    $output | Add-Member -MemberType NoteProperty -Name KVAShadowPcidEnabled -Value $SpeculationControlSettings.KVAShadowPcidEnabled
    $output | Add-Member -MemberType NoteProperty -Name OSMitigationRegKeySet -Value $SystemInformation.OSMitigationRegKeySet
    $output | Add-Member -MemberType NoteProperty -Name AVCompatibility -Value $SystemInformation.AVCompatibility
    $output | Add-Member -MemberType NoteProperty -Name MinVmVersionForCpuBasedMitigations -Value $SystemInformation.MinVmVersionForCpuBasedMitigations  
    $output | Add-Member -MemberType NoteProperty -Name InstalledUpdates -Value $SystemInformation.InstalledUpdates
    $output | Add-Member -MemberType NoteProperty -Name Uptime -Value $SystemInformation.Uptime
    $output | Add-Member -MemberType NoteProperty -Name ExecutionDate -Value $SystemInformation.ExecutionDate
    $output
}

if ($ComputerName) {
    $SessionOption = New-PSSessionOption -NoMachineProfile
    $CimSession = New-PSSession -ComputerName $ComputerName -SessionOption $SessionOption

    Invoke-Parallel -InputObject $CimSession -ScriptBlock {
        Invoke-Command -ScriptBlock $GetMeltdownStatusInformation -Session $_
    } -ImportVariable

    $CimSession | Remove-CimSession -ErrorAction SilentlyContinue
}
else {
    . $GetMeltdownStatusInformation
}