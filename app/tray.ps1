# Proxy Bypass tray controller.
# Keeps an icon in the notification area while the backend runs; can reopen the
# window, toggle the PC proxy and stop everything. Closing the browser window
# leaves this icon (and the app) alive.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$base = 'http://127.0.0.1:8077'
$backendPort = 8077
$browser = @(
    'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
    'C:\Program Files\Google\Chrome\Application\chrome.exe'
) | Where-Object { Test-Path $_ } | Select-Object -First 1

function Write-TrayLog([string]$message) {
    try {
        $logPath = Join-Path $env:LOCALAPPDATA 'ProxyApp\data\tray.log'
        $dir = Split-Path $logPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Add-Content -LiteralPath $logPath -Value ("{0} {1}" -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'), $message)
    } catch {}
}

function Test-Backend {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $backendPort, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(800)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        try { $client.Close() } catch {}
    }
}

function Open-Window {
    if (-not $browser) { return }
    Start-Process -FilePath $browser -ArgumentList @("--app=$base/", '--window-size=1180,860', '--no-first-run')
}

function Invoke-Api([string]$method, [string]$path, $body) {
    try {
        $params = @{ Uri = "$base$path"; Method = $method; TimeoutSec = 15; UseBasicParsing = $true }
        if ($null -ne $body) {
            $params.ContentType = 'application/json'
            $params.Body = ($body | ConvertTo-Json -Compress)
        }
        return Invoke-RestMethod @params
    } catch {
        return $null
    }
}

$tray = New-Object System.Windows.Forms.NotifyIcon
$tray.Icon = [System.Drawing.SystemIcons]::Application
$tray.Text = 'Proxy Bypass'
$tray.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$openItem = $menu.Items.Add('Открыть окно')
$openItem.add_Click({ Open-Window })

$toggleItem = $menu.Items.Add('Включить / выключить прокси на ПК')
$toggleItem.add_Click({
    $pc = Invoke-Api 'GET' '/api/pc' $null
    if ($null -eq $pc) { return }
    $want = -not [bool]$pc.pcProxyEnabled
    Invoke-Api 'POST' '/api/pc/toggle' @{ enabled = $want } | Out-Null
})

$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null

$closeItem = $menu.Items.Add('Закрыть полностью')
$closeItem.add_Click({
    Invoke-Api 'POST' '/api/shutdown' @{} | Out-Null
})

$tray.ContextMenuStrip = $menu
$tray.add_DoubleClick({ Open-Window })

# Exit as soon as the backend is gone (full shutdown, crash or manual stop).
Write-TrayLog 'tray started'
while ($true) {
    Start-Sleep -Seconds 4
    $alive = Test-Backend
    Write-TrayLog ("backend alive: {0}" -f $alive)
    if (-not $alive) {
        Write-TrayLog 'backend gone, exiting'
        $tray.Visible = $false
        $tray.Dispose()
        exit 0
    }
}
