# Proxy Bypass tray controller.
# A real WinForms message loop: without it the icon may not appear and the menu
# items never receive clicks.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

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

function Open-Window {
    if (-not $browser) { return }
    Write-TrayLog 'open window from tray'
    Start-Process -FilePath $browser -ArgumentList @("--app=$base/", '--window-size=1180,860', '--no-first-run')
}

$tray = New-Object System.Windows.Forms.NotifyIcon
$tray.Icon = [System.Drawing.SystemIcons]::Application
$tray.Text = 'Proxy Bypass'
$tray.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip

$openItem = New-Object System.Windows.Forms.ToolStripMenuItem('Открыть окно')
$openItem.add_Click({ Open-Window })
$menu.Items.Add($openItem) | Out-Null

$toggleItem = New-Object System.Windows.Forms.ToolStripMenuItem('Включить / выключить прокси на ПК')
$toggleItem.add_Click({
    $pc = Invoke-Api 'GET' '/api/pc' $null
    if ($null -eq $pc) { return }
    $want = -not [bool]$pc.pcProxyEnabled
    Invoke-Api 'POST' '/api/pc/toggle' @{ enabled = $want } | Out-Null
    Write-TrayLog ("toggled pc proxy -> {0}" -f $want)
})
$menu.Items.Add($toggleItem) | Out-Null

$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null

$closeItem = New-Object System.Windows.Forms.ToolStripMenuItem('Закрыть полностью')
$closeItem.add_Click({
    Write-TrayLog 'full shutdown requested'
    Invoke-Api 'POST' '/api/shutdown' @{} | Out-Null
    $script:closing = $true
})
$menu.Items.Add($closeItem) | Out-Null

$tray.ContextMenuStrip = $menu
$tray.add_DoubleClick({ Open-Window })
$tray.add_MouseClick({
    param($sender, $eventArgs)
    if ($eventArgs.Button -eq [System.Windows.Forms.MouseButtons]::Left) { Open-Window }
})

# Poll the backend with a WinForms timer so clicks and the timer share one loop.
$script:closing = $false
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 4000
$timer.add_Tick({
    if ($script:closing) { return }
    $alive = Test-Backend
    if (-not $alive) {
        Write-TrayLog 'backend gone, exiting'
        $timer.Stop()
        $tray.Visible = $false
        $tray.Dispose()
        [System.Windows.Forms.Application]::Exit()
    }
})
$timer.Start()

Write-TrayLog 'tray started'
try {
    [System.Windows.Forms.Application]::Run()
} finally {
    $timer.Stop()
    $tray.Visible = $false
    $tray.Dispose()
    Write-TrayLog 'tray stopped'
}
