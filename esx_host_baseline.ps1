# esx_host_baseline.ps1, 15-FEB-13, ABr
#
# Create/maintain ESXi host file integrity baseline
# 
# Change Log:
# 15-FEB-13, ABr: Initial creation

########################################################################
# utilities and setup
$global:UTILS_SCRIPTPATH = $MyInvocation.MyCommand.Path
$global:UTILS_SCRIPTDIR = Split-Path $global:UTILS_SCRIPTPATH
$global:UTILS_UTILITIES = $global:UTILS_SCRIPTDIR + '\ps_utils.ps1'
. $global:UTILS_UTILITIES
$global:APGPROXY_LOGNAME = 'esx_host_baseline.log'
Add-vCLIfunction

########################################################################
# globals
$global:ESX_HOST_BASELINE_DATA = $global:UTILS_SCRIPTDIR + '\data'
$global:ESX_HOST_BASELINE_EXT_ORIG = '.baseline'
$global:ESX_HOST_BASELINE_EXT_WEEKLY = '.weekly'
$global:ESX_HOST_HASH_EXT = '-hash'
#
# get hash file
function Get-EsxHostBaseline-FileHashName {
  param(
    [Parameter(Mandatory=$true)][string] $BaseFile
  )

  # get the hash file and save to disk
  $hashFile = $BaseFile + $global:ESX_HOST_HASH_EXT
  return $hashFile
}
#
# store hash
function Write-EsxHostBaseline-FileHash {
  param(
    [Parameter(Mandatory=$true)][string] $File
  )

  # get the hash file and save to disk
  $hash = Get-ChildItem $File | Get-FileHash
  $hashFile = $File + $global:ESX_HOST_HASH_EXT
  $hash.Hash > $hashFile
  return $true
}
#
# Get folder for ESXi host
function Get-EsxHostBaseline-EsxHostDir {
  param(
    [Parameter(Mandatory=$true)][string] $EsxHost
  )

  # first create data directory
  if (-not (Test-Path $global:ESX_HOST_BASELINE_DATA)) {
    New-Item -ItemType directory -Path $global:ESX_HOST_BASELINE_DATA
  }

  # now build the ESX host folder
  $esxHostFolder = $global:ESX_HOST_BASELINE_DATA + '\' + $EsxHost
  if (-not (Test-Path $esxHostFolder)) {
    New-Item -ItemType directory -Path $esxHostFolder
  }

  # return the result
  return $esxHostFolder
}
#
# Create path to ESX host info
function Get-EsxHostBaseline-EsxHostPath {
  param(
    [Parameter(Mandatory=$true)][string] $EsxHost,
    [Parameter(Mandatory=$true)][string] $File
  )

  # first access the ESXi host folder
  $esxHostFolder = Get-EsxHostBaseline-EsxHostDir $EsxHost

  # finally build the full path and return it
  $result = $esxHostFolder + '\' + $File
  return $result
}
#
# write an actual config from a host
function Write-EsxHostBaseline-Config {
  param(
    [Parameter(Mandatory=$true)][string] $EsxHost,
    [Parameter(Mandatory=$true)][string] $ConfigPath
  )

  # perform the command
  vicfg-cfgbackup -save -server $EsxHost `
    -username $global:PS_UTILS_ESXPROXY_UID `
    -password $global:PS_UTILS_ESXPROXY_PWD `
    $ConfigPath

  # auto-write a hash
  return Write-EsxHostBaseline-FileHash $ConfigPath
}
#
# get the baseline config path
function Get-EsxHostBaseline-BaselinePath {
  param(
    [Parameter(Mandatory=$true)][string] $EsxHost
  )

  # construct file
  $file = $EsxHost + $global:ESX_HOST_BASELINE_EXT_ORIG
  $baselinePath = Get-EsxHostBaseline-EsxHostPath $EsxHost $file
  return $baselinePath
}
#
# get the weekly config path
function Get-EsxHostBaseline-WeeklyPath {
  param(
    [Parameter(Mandatory=$true)][string] $EsxHost
  )

  # construct file
  $today = Get-Date -format yyyyMMdd
  $file = $EsxHost + '-' + $today + $global:ESX_HOST_BASELINE_EXT_WEEKLY
  $weeklyPath = Get-EsxHostBaseline-EsxHostPath $EsxHost $file
  return $weeklyPath
}
#
# create baseline for ESX host if necessary
function Write-EsxHostBaseline-Baseline {
  param(
    [Parameter(Mandatory=$true)][string] $EsxHost
  )

  # construct file
  $baselinePath = Get-EsxHostBaseline-BaselinePath $EsxHost
  if (-not (Test-Path $baselinePath)) {
    Write-HostAndLog 'Creating baseline...'
    return Write-EsxHostBaseline-Config $EsxHost $baselinePath
  }
  return $true
}
#
# create weekly file integrity check
function Write-EsxHostBaseline-Weekly {
  param(
    [Parameter(Mandatory=$true)][string] $EsxHost
  )

  # first ensure a baseline exists
  if (-not (Write-EsxHostBaseline-Baseline $EsxHost)) { return $false }

  # construct file
  $weeklyPath = Get-EsxHostBaseline-WeeklyPath $EsxHost
  Write-HostAndLog 'Creating weekly config...'
  if (-not (Write-EsxHostBaseline-Config $EsxHost $weeklyPath)) { return $false }
}
#
# compare weekly and baseline configs for changes
function Compare-EsxHostBaseline-Current {
  param(
    [Parameter(Mandatory=$true)][string] $EsxHost
  )

  # baseline must exist
  $baselinePath = Get-EsxHostBaseline-BaselinePath $EsxHost
  if (-not (Test-Path $baselinePath)) {
    Write-HostAndLog "Baseline config '$baselinePath' does not exist"
    return $false
  }

  # get the hash file associated with baseline
  $baselineHash = Get-EsxHostBaseline-FileHashName $baselinePath | gci

  # get current week
  $esxHostDir = Get-EsxHostBaseline-EsxHostDir $EsxHost
  $hashExt = $global:ESX_HOST_BASELINE_EXT_WEEKLY + $global:ESX_HOST_HASH_EXT
  $hashSpec = $esxHostDir + "\*" + $hashExt
  $latestWeekly = gci $hashSpec | sort LastWriteTime | select -last 1
  if ((-not $latestWeekly) -or (-not $latestWeekly.Exists)) {
    Write-HostAndLog "No latest weekly config in '$hashSpec'"
    return $false
  }

  # read hash contents
  $baselineHashContents = gc $baselineHash
  $baselineHashContents
  $latestWeeklyHashContents = gc $latestWeekly
  $latestWeeklyHashContents

  # prepare the display
  $hashDisplay = $latestWeekly.FullName + " ($latestWeeklyHashContents) against " + `
    $baselineHash.FullName + " ($baselineHashContents)"

  # do the comparison of the content - which is simply a hash
  $result = $baselineHashContents -eq $latestWeeklyHashContents
  $result
  $result | Get-Member
  if (-not $result) {
    $msg = "MISMATCH: " + $hashDisplay
    Write-HostAndLog $msg
    return $false
  }

  # success - baseline unchanged compared to weekly
  $msg = "OK: " + $hashDisplay
  Write-HostAndLog $msg
  return $true
}

