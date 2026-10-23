param(
  [string]$Source = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) '..\insp\pentestkit-10.0.0-release'),
  [string]$OutputDirectory = (Join-Path $env:LOCALAPPDATA 'cert-x\ptk\v10'),
  [string]$ExtensionId = ''
)
$ErrorActionPreference = 'Stop'
$nodeCommand = Get-Command node -ErrorAction Stop
$taskArguments = @((Join-Path $PSScriptRoot 'prepare.cjs'), '--source', $Source, '--output', $OutputDirectory)
if ($ExtensionId) { $taskArguments += @('--extension-id', $ExtensionId) }
& $nodeCommand.Source @taskArguments
if ($LASTEXITCODE -ne 0) { throw "PTK preparation failed (exit $LASTEXITCODE). Existing files were preserved." }
