Add-Type -AssemblyName System.Drawing
$size = 256
$bmp = New-Object System.Drawing.Bitmap($size, $size)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'AntiAlias'
$g.Clear([System.Drawing.Color]::Transparent)
$brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush((New-Object System.Drawing.Rectangle(0,0,$size,$size)), [System.Drawing.Color]::FromArgb(255,17,24,39), [System.Drawing.Color]::FromArgb(255,15,118,110), 45)
$g.FillEllipse($brush, 8, 8, $size-16, $size-16)
$font = New-Object System.Drawing.Font('Segoe UI', 104, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
$fmt = New-Object System.Drawing.StringFormat
$fmt.Alignment = 'Center'; $fmt.LineAlignment = 'Center'
$white = [System.Drawing.Brushes]::White
$g.DrawString('PB', $font, $white, (New-Object System.Drawing.RectangleF(0,0,$size,$size)), $fmt)
$g.Dispose()
$ms = New-Object System.IO.MemoryStream
$bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
$png = $ms.ToArray()
$fs = [System.IO.File]::Create((Join-Path $PSScriptRoot 'app.ico'))
$bw = New-Object System.IO.BinaryWriter($fs)
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]1)
$bw.Write([Byte]0); $bw.Write([Byte]0); $bw.Write([Byte]0); $bw.Write([Byte]0)
$bw.Write([UInt16]1); $bw.Write([UInt16]32)
$bw.Write([UInt32]$png.Length); $bw.Write([UInt32]22)
$bw.Write($png)
$bw.Close()
