param([string]$TargetDirectory,[string]$NodePath,[string]$ExtensionId,[string]$RegistryPath,[switch]$GenerateOnly)
$ErrorActionPreference = 'Stop'
$parentDirectory = [IO.Directory]::GetParent($TargetDirectory).FullName
$transaction = [Guid]::NewGuid().ToString('N')
$stage = Join-Path $parentDirectory "$ExtensionId.stage-$transaction"
$backup = Join-Path $parentDirectory "$ExtensionId.previous-$transaction"
function Assert-InstallPath([string]$candidate) {
  $absolute = [IO.Path]::GetFullPath($candidate)
  if (-not $absolute.StartsWith($parentDirectory.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Install transaction escaped its target directory.' }
  if ((Test-Path -LiteralPath $absolute) -and (Get-Item -LiteralPath $absolute -Force).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'Install transaction does not follow directory links.' }
}
function Get-InstallHash([string]$file) {
  $algorithm = [Security.Cryptography.SHA256]::Create()
  $stream = [IO.File]::OpenRead($file)
  try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)) }
  finally { $stream.Dispose(); $algorithm.Dispose() }
}
foreach ($candidate in @($TargetDirectory,$stage,$backup)) { Assert-InstallPath $candidate }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$previousMoved = $false
$published = $false
try {
  # Preserve unrelated installed files, but never follow links into other trees.
  if (Test-Path -LiteralPath $TargetDirectory) {
    if (@(Get-ChildItem -LiteralPath $TargetDirectory -Recurse -Force | Where-Object { $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) }).Count) { throw 'Existing installation contains directory links; update it explicitly.' }
    foreach ($entry in Get-ChildItem -LiteralPath $TargetDirectory -Force) { Copy-Item -LiteralPath $entry.FullName -Destination $stage -Recurse -Force }
  }
  $managedFiles = @{}
  foreach ($name in @('ki-host.js','jobs.js')) { $managedFiles[$name] = Join-Path $PSScriptRoot $name }
  foreach ($entry in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'security') -File -Filter '*.cjs') { $managedFiles['security\' + $entry.Name] = $entry.FullName }
  foreach ($name in @('package.json','package-lock.json','assets.lock.json','requirements.lock','README.md','THIRD_PARTY_NOTICES.md')) { $managedFiles['security\runtime\' + $name] = Join-Path (Join-Path $PSScriptRoot '..\security\runtime') $name }
  foreach ($relative in $managedFiles.Keys) {
    $destination = Join-Path $stage $relative
    New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($destination)) -Force | Out-Null
    Copy-Item -LiteralPath $managedFiles[$relative] -Destination $destination -Force
    if ((Get-InstallHash $destination) -ne (Get-InstallHash $managedFiles[$relative])) { throw "Copied native component differs: $relative" }
  }
  & $NodePath --check (Join-Path $stage 'ki-host.js')
  if ($LASTEXITCODE -ne 0) { throw 'Staged native host failed its syntax check.' }
  & $NodePath -e "const h=require(process.argv[1]);h.dispatch('status',{}).then(s=>{if(!s.features.includes('security_runtime_v1'))process.exit(1)}).catch(()=>process.exit(1));" (Join-Path $stage 'ki-host.js')
  if ($LASTEXITCODE -ne 0) { throw 'Staged native host failed its dependency check.' }
  $scriptPath = Join-Path $TargetDirectory 'ki-host.js'
  $launcherPath = Join-Path $TargetDirectory 'launch.cmd'
  $launcher = "@echo off`r`nchcp 65001 >nul`r`nsetlocal DisableDelayedExpansion`r`n`"$NodePath`" `"$scriptPath`"`r`n"
  [IO.File]::WriteAllText((Join-Path $stage 'launch.cmd'), $launcher, (New-Object Text.UTF8Encoding($false)))
  $manifestPath = Join-Path $TargetDirectory 'com.cert_x.host.json'
  $manifest = @{ name = 'com.cert_x.host'; description = 'cert-x local commands, files and stdio MCP bridge'; path = $launcherPath; type = 'stdio'; allowed_origins = @("chrome-extension://$ExtensionId/") } | ConvertTo-Json
  [IO.File]::WriteAllText((Join-Path $stage 'com.cert_x.host.json'), $manifest, (New-Object Text.UTF8Encoding($false)))
  if (Test-Path -LiteralPath $TargetDirectory) {
    Assert-InstallPath $TargetDirectory; Assert-InstallPath $backup
    Move-Item -LiteralPath $TargetDirectory -Destination $backup
    $previousMoved = $true
  }
  Assert-InstallPath $stage; Assert-InstallPath $TargetDirectory
  Move-Item -LiteralPath $stage -Destination $TargetDirectory
  $published = $true
  if (-not $GenerateOnly) { New-Item -Path $RegistryPath -Force | Out-Null; Set-Item -LiteralPath $RegistryPath -Value $manifestPath }
} catch {
  if ($published) { Assert-InstallPath $TargetDirectory; Remove-Item -LiteralPath $TargetDirectory -Recurse -Force }
  if ($previousMoved) { Assert-InstallPath $backup; Assert-InstallPath $TargetDirectory; Move-Item -LiteralPath $backup -Destination $TargetDirectory }
  throw
} finally {
  if (Test-Path -LiteralPath $stage) { Assert-InstallPath $stage; Remove-Item -LiteralPath $stage -Recurse -Force }
}
if (Test-Path -LiteralPath $backup) {
  try { Assert-InstallPath $backup; Remove-Item -LiteralPath $backup -Recurse -Force }
  catch { Write-Warning "Previous host files are still in use; retained at $backup" }
}
