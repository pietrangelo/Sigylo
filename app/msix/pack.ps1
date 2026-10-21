# Packs the Windows build into an MSIX for the Microsoft Store, which signs it
# on upload. Run from app/ after `cargo tauri build` on Windows; writes
# target/msix/Sigylo_<version>.0_x64.msix.
param(
  [string]$Exe = "target/release/sigylo-app.exe",
  [string]$Out = "target/msix"
)
$ErrorActionPreference = "Stop"

$version = (Get-Content tauri.conf.json -Raw | ConvertFrom-Json).version
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw "version $version is not major.minor.patch" }

$layout = Join-Path $Out "layout"
Remove-Item -Recurse -Force $Out -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force (Join-Path $layout "Assets") | Out-Null
Copy-Item $Exe (Join-Path $layout "Sigylo.exe")
foreach ($logo in "StoreLogo", "Square150x150Logo", "Square44x44Logo") {
  Copy-Item "icons/$logo.png" (Join-Path $layout "Assets")
}
(Get-Content msix/AppxManifest.xml -Raw).Replace("{{VERSION}}", "$version.0") |
  Set-Content (Join-Path $layout "AppxManifest.xml") -Encoding utf8NoBOM

$makeappx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" |
  Sort-Object FullName -Descending | Select-Object -First 1
if (-not $makeappx) { throw "makeappx.exe not found: install the Windows SDK" }
# makeappx validates the manifest against the schema and fails on any error.
& $makeappx.FullName pack /o /d $layout /p (Join-Path $Out "Sigylo_$version.0_x64.msix")
if ($LASTEXITCODE -ne 0) { throw "makeappx failed with $LASTEXITCODE" }
