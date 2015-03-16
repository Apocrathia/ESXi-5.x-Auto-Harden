# ps_utils.ps1, 15-FEB-13, ABr
#
# PowerShell utilities to support ESX tasks
# 
# Change Log:
# 15-FEB-13, ABr: Initial creation
#
#######################################################################
# bogus globals to allow interface to vCLI commands
$global:PS_UTILS_ESXPROXY_UID = $Env:PS_UTILS_ESXPROXY_UID
if (-Not $global:PS_UTILS_ESXPROXY_UID) {
  Write-Error 'You must define PS_UTILS_ESXPROXY_UID in the environment'
}
$global:PS_UTILS_ESXPROXY_PWD = $Env:PS_UTILS_ESXPROXY_PWD
if (-Not $global:PS_UTILS_ESXPROXY_PWD) {
  Write-Error 'You must define PS_UTILS_ESXPROXY_PWD in the environment'
}
#######################################################################
# Log functions
########################################################################
#
# Log Functions
# Function to Check Log Size and Rotate as Needed
function RotateLog($log) {
  $threshold = 15 # Size of File in Megabytes when Log Should Be Rotated
  $file = Get-Item "$log" # Get Log File
  $filedir = $file.directory.fullname # Get Log Directory
  $server = HostName
  $filesize = $file.length/1MB # Get Current Size of File
  $datetime = Get-Date -uformat "%Y%m%d-%H%M" # Get Current Date and Time
  $fdatetime = Get-Date -uformat "%B %e, %Y - %H%M hours" # Get Formatted Current Date and Time
  $arcdir = "$filedir\archive" # Specify Log Archive Directory
  if ((Test-Path -Path $arcdir -PathType container) -ne $True) # Verify that the Archive Directory Exists - If not, Create it
  {
    $result = New-Item $arcdir -Type directory # Create Directory if it does not Exist
  }
  if ($filesize -gt $threshold) { # Compare Log File Size to Specified Threshold
    $filename = $file.name -replace $file.extension,"" # Remove File Extension from Name
    $newname = "${filename}_${datetime}.log" # Specify New Name for Archived Log
    Rename-Item -Path $file.fullname -NewName $newname # Rotate Current Log to Archive
    Move-Item $newname -Dest "$arcdir" # Move Archived Log to Archive Directory
    $rotationmessage = "-----------------------------------------------------------
Log rotation occured - $fdatetime
Rotated log available here: ${arcdir}\${newname} on $server
-----------------------------------------------------------
"   # Log Rotation Message
    Write-Host "$rotationmessage" # Echo Log Rotation Message to Console if Active
    echo "$rotationmessage" | Out-File -FilePath "$log" -Append # Create New Log and Record Log Rotation in New Log

    # see if we need to delete any logs
    $compareDate = (Get-Date).AddDays(-7) #Number of days to keep logs for
    $currentDate = Get-Date #The current date for the log file this script creates
    # Appends a list of the files to be deleted to the bottom of this scripts log file
    #Get-ChildItem $logsToRotate\*.log | Where-Object {$_.LastWriteTime -lt $compareDate} >> $rotateLog #Appends a list of the files to be deleted to the bottom of this scripts log file
    # Deletes files older then the specified amount of time
    Get-ChildItem $arcdir\*.log | Where-Object {$_.LastWriteTime -lt $compareDate} | Remove-Item #Deletes files older then the specified amount of time
  }
}
#
# General output function
$global:APGPROXY_PROCESS = [System.Diagnostics.Process]::GetCurrentProcess()
$global:APGPROXY_PID = $global:APGPROXY_PROCESS.Id
$global:APGPROXY_LOGNAME = 'ApgProxy.log'
function Write-HostAndLog {
  param(
    [Parameter(Mandatory=$false)][string] $Message,
    [Parameter(Mandatory=$false)][string] $logFile = $global:APGPROXY_LOGNAME
  )
  Write-Host($Message)
  if ($logFile) {
    $log = Join-Path (Get-Location) $logFile
  } else {
    $log = Join-Path (Get-Location) $global:APGPROXY_LOGNAME
  } #if
  $datetime = Get-Date -uformat "%Y%m%d-%H%M%S" # Get Current Date and Time
  echo "$datetime $global:APGPROXY_PID $Message" | Out-File -FilePath "$log" -Append # Create New Log and Record Log Rotation in New Log
  RotateLog($log) # Call Log Rotation Function
}
#
#######################################################################
# Get file hash - see http://www.theinfraguy.com/2011/11/powershell-generate-md5-or-sha-file.html
function Get-FileHash {
<#
.Synopsis
Compute the hash value of a file based on the SHA1 or SHA256 algorithms.
.Description
Returns a string that represents the hash
.Parameter File
The file to process. Either piped from Get-ChildItem or the fullpath as a string
.Parameter Algorithm
SHA1 or SHA256
.Example
dir c:\temp | ?{-not $_.PSIsContainer} | Get-FileHash
#>
[CmdletBinding(
SupportsShouldProcess=$False,
SupportsTransactions=$False,
ConfirmImpact="Low",
DefaultParameterSetName="")]
param(
[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)]
[System.IO.FileSystemInfo]$file
,
[Parameter(Position=1,Mandatory=$false)]
[ValidateSet("SHA1","SHA256")]
[string]$Algorithm="SHA1"
)
BEGIN{}
PROCESS{
 
# Silently ignore folders
if(($file -as [System.IO.FileInfo]) -eq $null){
Write-Debug "Unsupported input object - '$($File.Fullname)'"
return        
}
 
$Property=@{
Filename = $file.Name
Fullname = $file.Fullname
Hash = ""
Result = ""
Algorithm = $Algorithm
}
 
Switch($Algorithm){
"SHA1"{
$alg = new-object System.Security.Cryptography.SHA1CryptoServiceProvider
}
 
"SHA256"{
$alg = new-object System.Security.Cryptography.SHA256CryptoServiceProvider
}
}#switch
 
try{
 
$stream = $file.OpenRead()
$HashBuilder = New-Object System.Text.StringBuilder
$alg.ComputeHash($stream) | ForEach-Object { [void] $HashBuilder.Append($_.ToString("x2")) }
$Property.Item("Hash") = $HashBuilder.ToString()
$stream.close()
 
$Property.Item("Result") = "Success"
 
}catch{
if ($stream -ne $null){ $stream.Close() }
$Property.Item("Result") = "Error::Failed, message '$_'"
}
 
 
New-Object -Typename PSObject -Property $Property
}
END{}
 
}
#
#######################################################################
# Run vCLI from PowerShell - see http://rvdnieuwendijk.com/2011/07/21/how-to-run-vmware-vsphere-cli-perl-scripts-from-powercli/
function Add-vCLIfunction {
  <#
  .SYNOPSIS
    Adds the VMware vSphere Command-Line Interface perl scripts as PowerCLI functions.

  .DESCRIPTION
    Adds all the VMware vSphere Command-Line Interface perl scripts as PowerCLI functions.
    VMware vSphere Command-Line Interface has to be installed on the system where you run this function.
    You can download the VMware vSphere Command-Line Interface from:
    http://communities.vmware.com/community/vmtn/server/vsphere/automationtools/vsphere_cli?view=overview

  .EXAMPLE
    Add-vCLIfunction
    Adds all the VMware vSphere Command-Line Interface perl scripts as PowerCLI functions to your PowerCLI session.

  .COMPONENT
    VMware vSphere PowerCLI

  .NOTES
    Author:  Robert van den Nieuwendijk
    Date:    21-07-2011
    Version: 1.0
  #>

  process {
    # Test if VMware vSphere Command-Line Interface is installed
    $vcliPath = ''
    If ($env:vclipath) {
      # clear out any bogus quotes
      $vcliPath = $env:vclipath -replace '"', ''
      # point to perl scripts
      $vcliPath = $vcliPath + '\..\..\bin'
    } else {
      $vcliPath = "$env:ProgramFiles\VMware\VMware vSphere CLI\perl\bin\"
    }
    #Write-Host $vcliPath
    If (-not (Test-Path -Path $vcliPath)) {
      Write-Error "VMware vSphere CLI should be installed before running this function."
    } else {
      # Add all the VMware vSphere CLI perl scripts as PowerCLI functions
      Get-ChildItem -Path "$vcliPath\*.pl" | ForEach-Object {
        #Write-Host $_
        $Function = "function global:$($_.Name.Split('.')[0]) { perl '$vcliPath\$($_.Name)'"
        $Function += ' $args }'
        Invoke-Expression $Function
      }
    }
  }
}

