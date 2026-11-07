# Установка Proxy Bypass в %LOCALAPPDATA%\ProxyApp + автозапуск при входе в Windows.
# Автозапуск делается ярлыком в папке «Автозагрузка» — права администратора не нужны.
$ErrorActionPreference = 'Stop'

$source = $PSScriptRoot
$target = Join-Path $env:LOCALAPPDATA 'ProxyApp'

Write-Host "Копирую приложение в $target ..."
New-Item -ItemType Directory -Force -Path $target | Out-Null
foreach ($item in @('app', 'start.cmd', 'proxy-app.vbs', 'README.md')) {
    Copy-Item (Join-Path $source $item) $target -Recurse -Force
}
$dataTarget = Join-Path $target 'data'
New-Item -ItemType Directory -Force -Path $dataTarget | Out-Null
$dataSource = Join-Path $source 'data\config.json'
$dataExisting = Join-Path $dataTarget 'config.json'
if ((Test-Path $dataSource) -and -not (Test-Path $dataExisting)) {
    Copy-Item $dataSource $dataTarget -Force
}

Write-Host 'Создаю ярлык в меню «Пуск» ...'
$shell = New-Object -ComObject WScript.Shell
$startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$shortcut = $shell.CreateShortcut((Join-Path $startMenu 'Proxy Bypass.lnk'))
$shortcut.TargetPath = Join-Path $target 'proxy-app.vbs'
$shortcut.WorkingDirectory = $target
$shortcut.WindowStyle = 7
$shortcut.Description = 'Proxy Bypass — обход блокировок'
$shortcut.Save()

Write-Host 'Регистрирую автозапуск при входе в Windows ...'
$startup = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
$auto = $shell.CreateShortcut((Join-Path $startup 'Proxy Bypass.lnk'))
$auto.TargetPath = Join-Path $target 'proxy-app.vbs'
$auto.WorkingDirectory = $target
$auto.WindowStyle = 7
$auto.Description = 'Proxy Bypass — автозапуск'
$auto.Save()

Write-Host ''
Write-Host 'Готово. Приложение установлено в:' $target
Write-Host 'Автозапуск: ярлык «Proxy Bypass» в папке «Автозагрузка» Windows.'
Write-Host 'Запустить сейчас: start.cmd или ярлык «Proxy Bypass» в меню Пуск.'
Write-Host ''
Write-Host 'Убрать автозапуск: удалите ярлык Proxy Bypass из папки Startup.'
