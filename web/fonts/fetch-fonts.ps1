# Fetch the self-hosted brand fonts into web/public/fonts/ (OFL 1.1). Run once.
$ErrorActionPreference = 'Stop'
$dest = Join-Path $PSScriptRoot '..\public\fonts'
New-Item -ItemType Directory -Force -Path $dest | Out-Null

$base = 'https://cdn.jsdelivr.net/fontsource/fonts'
$files = @{
  "$base/space-grotesk@latest/latin-400-normal.woff2"  = 'SpaceGrotesk-Regular.woff2'
  "$base/space-grotesk@latest/latin-500-normal.woff2"  = 'SpaceGrotesk-Medium.woff2'
  "$base/space-grotesk@latest/latin-600-normal.woff2"  = 'SpaceGrotesk-SemiBold.woff2'
  "$base/jetbrains-mono@latest/latin-400-normal.woff2" = 'JetBrainsMono-Regular.woff2'
  "$base/jetbrains-mono@latest/latin-500-normal.woff2" = 'JetBrainsMono-Medium.woff2'
  "$base/ibm-plex-mono@latest/latin-400-normal.woff2"  = 'IBMPlexMono-Regular.woff2'
  "$base/fira-code@latest/latin-400-normal.woff2"      = 'FiraCode-Regular.woff2'
}

Write-Host "Fetching brand fonts into $dest"
foreach ($url in $files.Keys) {
  $out = Join-Path $dest $files[$url]
  Write-Host "  $($files[$url])"
  Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
}
Write-Host 'Done. These files are gitignored; they ship with the Vite build.'
