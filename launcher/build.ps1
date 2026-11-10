# Builds the Windows launcher (ProxyBypass.exe) around the Node.js server.
# Requires: .NET Framework 4.x csc (ships with Windows) and internet for the
# WebView2 SDK on the first run.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$lib = Join-Path $here 'lib'
$dist = Join-Path $here 'dist'
$version = '1.0.4314.35'

New-Item -ItemType Directory -Force -Path $lib, $dist | Out-Null
if (-not (Test-Path (Join-Path $lib 'Microsoft.Web.WebView2.WinForms.dll'))) {
  $nupkg = Join-Path $env:TEMP 'webview2.nupkg'
  Invoke-WebRequest -UseBasicParsing -Uri "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/$version/microsoft.web.webview2.$version.nupkg" -OutFile $nupkg
  $tar = "$env:WINDIR\System32\tar.exe"
  & $tar -xf $nupkg -C $lib 'lib/net462/Microsoft.Web.WebView2.Core.dll' 'lib/net462/Microsoft.Web.WebView2.WinForms.dll' 'build/native/x64/WebView2Loader.dll'
  Move-Item (Join-Path $lib 'lib\net462\*.dll') $lib -Force
  Move-Item (Join-Path $lib 'build\native\x64\WebView2Loader.dll') $lib -Force
  Remove-Item (Join-Path $lib 'lib'), (Join-Path $lib 'build') -Recurse -Force
}

& $csc /nologo /target:winexe /platform:x64 /out:"$dist\ProxyBypass.exe" `
  /win32icon:"$here\app.ico" /win32manifest:"$here\app.manifest" `
  /r:System.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll `
  /r:"$lib\Microsoft.Web.WebView2.Core.dll" /r:"$lib\Microsoft.Web.WebView2.WinForms.dll" `
  "$here\Launcher.cs"

Copy-Item "$lib\*.dll" $dist -Force
Write-Output "built: $dist\ProxyBypass.exe"
