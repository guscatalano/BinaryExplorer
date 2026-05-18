# Generates BinaryExplorer icon assets: a charcoal rounded square with an
# amber "BE" monogram centered. Used at every size from 16px to 1240px.

Add-Type -AssemblyName System.Drawing

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir
$assets    = Join-Path $repoRoot 'Assets'
New-Item -ItemType Directory -Force -Path $assets | Out-Null

$Bg1    = [System.Drawing.Color]::FromArgb(255, 17, 17, 17)
$Bg2    = [System.Drawing.Color]::FromArgb(255, 38, 38, 38)
$Accent = [System.Drawing.Color]::FromArgb(255, 245, 158, 11)  # amber-500

function Add-RoundedRectPath {
    param($path, [int]$x, [int]$y, [int]$w, [int]$h, [int]$radius)
    if ($radius -le 0) {
        $path.AddRectangle([System.Drawing.Rectangle]::new($x, $y, $w, $h))
        return
    }
    $d = $radius * 2
    $path.AddArc($x,                  $y,                  $d, $d, 180, 90)
    $path.AddArc($x + $w - $d - 1,    $y,                  $d, $d, 270, 90)
    $path.AddArc($x + $w - $d - 1,    $y + $h - $d - 1,    $d, $d,   0, 90)
    $path.AddArc($x,                  $y + $h - $d - 1,    $d, $d,  90, 90)
    $path.CloseFigure()
}

function New-IconBitmap {
    param([int]$Width, [int]$Height)

    $bmp = New-Object System.Drawing.Bitmap $Width, $Height, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode      = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode  = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.TextRenderingHint  = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality

    $badge = [Math]::Min($Width, $Height)
    $offX  = [int](($Width  - $badge) / 2)
    $offY  = [int](($Height - $badge) / 2)

    # Background.
    $rect = [System.Drawing.Rectangle]::new($offX, $offY, $badge, $badge)
    $bgBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect, $Bg1, $Bg2, 45.0
    $cornerRadius = [int]($badge * 0.18)
    $bgPath = New-Object System.Drawing.Drawing2D.GraphicsPath
    Add-RoundedRectPath $bgPath $offX $offY $badge $badge $cornerRadius
    $g.FillPath($bgBrush, $bgPath)
    $bgBrush.Dispose(); $bgPath.Dispose()

    # "BE" monogram.
    $fontPx = [single]($badge * 0.55)
    $candidates = @('Segoe UI Variable Display', 'Segoe UI', 'Arial Black')
    $font = $null
    foreach ($name in $candidates) {
        try {
            $font = New-Object System.Drawing.Font $name, $fontPx, ([System.Drawing.FontStyle]::Bold), ([System.Drawing.GraphicsUnit]::Pixel)
            break
        } catch { }
    }
    if ($null -eq $font) {
        $font = New-Object System.Drawing.Font 'Arial', $fontPx, ([System.Drawing.FontStyle]::Bold), ([System.Drawing.GraphicsUnit]::Pixel)
    }
    $brush = New-Object System.Drawing.SolidBrush $Accent
    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment     = [System.Drawing.StringAlignment]::Center
    $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
    # Nudge upward slightly to compensate for font baseline padding.
    $cx = [single]($offX + $badge / 2)
    $cy = [single]($offY + $badge / 2 - $badge * 0.03)
    $g.DrawString('BE', $font, $brush, $cx, $cy, $sf)

    $font.Dispose(); $brush.Dispose(); $sf.Dispose()
    $g.Dispose()
    return $bmp
}

function Save-Png { param([System.Drawing.Bitmap]$Bmp, [string]$Path)
    $Bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
}

function Save-Ico {
    param([int[]]$Sizes, [string]$OutPath)
    $bmps = @(); $pngBytes = @()
    foreach ($sz in $Sizes) {
        $b = New-IconBitmap -Width $sz -Height $sz
        $ms = New-Object System.IO.MemoryStream
        $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $pngBytes += ,@($ms.ToArray())
        $ms.Dispose()
        $bmps += $b
    }
    $fs = [System.IO.File]::Open($OutPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $w  = New-Object System.IO.BinaryWriter $fs
    try {
        $w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$Sizes.Count)
        $offset = 6 + ($Sizes.Count * 16)
        for ($i = 0; $i -lt $Sizes.Count; $i++) {
            $sz = $Sizes[$i]; $byteLen = $pngBytes[$i].Length
            $w.Write([byte]($sz -band 0xFF)); $w.Write([byte]($sz -band 0xFF))
            $w.Write([byte]0); $w.Write([byte]0)
            $w.Write([uint16]1); $w.Write([uint16]32)
            $w.Write([uint32]$byteLen); $w.Write([uint32]$offset)
            $offset += $byteLen
        }
        foreach ($b in $pngBytes) { $w.Write($b) }
    }
    finally {
        $w.Dispose(); $fs.Dispose()
        foreach ($b in $bmps) { $b.Dispose() }
    }
}

Save-Ico -Sizes @(16, 24, 32, 48, 64, 128, 256) -OutPath (Join-Path $assets 'AppIcon.ico')

$pngs = @(
    @{ Path = Join-Path $assets 'StoreLogo.png';                                          W = 50;   H = 50   },
    @{ Path = Join-Path $assets 'Square150x150Logo.scale-200.png';                        W = 300;  H = 300  },
    @{ Path = Join-Path $assets 'Square44x44Logo.scale-200.png';                          W = 88;   H = 88   },
    @{ Path = Join-Path $assets 'Square44x44Logo.targetsize-24_altform-unplated.png';     W = 24;   H = 24   },
    @{ Path = Join-Path $assets 'Square44x44Logo.targetsize-48_altform-lightunplated.png';W = 48;   H = 48   },
    @{ Path = Join-Path $assets 'LockScreenLogo.scale-200.png';                           W = 48;   H = 48   },
    @{ Path = Join-Path $assets 'Wide310x150Logo.scale-200.png';                          W = 620;  H = 300  },
    @{ Path = Join-Path $assets 'SplashScreen.scale-200.png';                             W = 1240; H = 600  }
)
foreach ($spec in $pngs) {
    $b = New-IconBitmap -Width $spec.W -Height $spec.H
    Save-Png -Bmp $b -Path $spec.Path
    $b.Dispose()
}
Write-Host "Wrote AppIcon.ico and $($pngs.Count) PNG assets"
