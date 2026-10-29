param(
  [Parameter(Mandatory = $true)][ValidatePattern('^[a-p]{32}$')][string]$ExtensionId,
  [ValidateSet('Chrome', 'Edge', 'Chromium')][string]$Browser = 'Chrome',
  [switch]$Uninstall,
  [switch]$GenerateOnly,
  [string]$OutputDirectory = (Join-Path $env:LOCALAPPDATA 'cert-x\native-host')
)
$ErrorActionPreference = 'Stop'
$hostName = 'com.cert_x.host'
$browserKey = @{ Chrome = 'Google\Chrome'; Edge = 'Microsoft\Edge'; Chromium = 'Chromium' }[$Browser]
$registryPath = "HKCU:\Software\$browserKey\NativeMessagingHosts\$hostName"
if ($Uninstall) {
  # Only unregister; preserve installed source and user data.
  if (Test-Path -LiteralPath $registryPath) { Remove-Item -LiteralPath $registryPath }
  Write-Output "Unregistered cert-x native host for $Browser."
  exit 0
}
$nodePath = (Get-Command node.exe -ErrorAction Stop).Source
$nodeVersion = & $nodePath --version
if ($LASTEXITCODE -ne 0 -or $nodeVersion -notmatch '^v(\d+)\.') { throw 'Could not determine Node.js version.' }
$nodeMajor = [int]$Matches[1]
if ($nodeMajor -lt 22) { throw 'Node.js 22 or newer is required.' }
$targetDirectory = [IO.Path]::GetFullPath((Join-Path (Join-Path $OutputDirectory $Browser) $ExtensionId))
if ($targetDirectory -match '[%\r\n!]' -or $nodePath -match '[%\r\n!]') { throw 'Installation paths cannot contain %, !, or newlines.' }
& (Join-Path $PSScriptRoot 'stage-install.ps1') -TargetDirectory $targetDirectory -NodePath $nodePath -ExtensionId $ExtensionId -RegistryPath $registryPath -GenerateOnly:$GenerateOnly
Write-Output "Native host files: $targetDirectory"
if ($GenerateOnly) { Write-Output 'Generated only; browser registration was not changed.' }
else { Write-Output "Installed for $Browser and extension $ExtensionId. Reload cert-x, then check Local computer status." }
