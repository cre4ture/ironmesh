param(
    [string]$OutFile = (Join-Path $PSScriptRoot "..\\assets\\windows\\ironmesh.ico")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing

function New-RoundedRectanglePath {
    param(
        [float]$X,
        [float]$Y,
        [float]$Width,
        [float]$Height,
        [float]$Radius
    )

    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $diameter = $Radius * 2.0

    $path.AddArc($X, $Y, $diameter, $diameter, 180, 90)
    $path.AddArc($X + $Width - $diameter, $Y, $diameter, $diameter, 270, 90)
    $path.AddArc($X + $Width - $diameter, $Y + $Height - $diameter, $diameter, $diameter, 0, 90)
    $path.AddArc($X, $Y + $Height - $diameter, $diameter, $diameter, 90, 90)
    $path.CloseFigure()

    return $path
}

function New-LinearBrush {
    param(
        [System.Drawing.PointF]$Start,
        [System.Drawing.PointF]$End,
        [string]$StartColor,
        [string]$EndColor
    )

    return New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $Start,
        $End,
        [System.Drawing.ColorTranslator]::FromHtml($StartColor),
        [System.Drawing.ColorTranslator]::FromHtml($EndColor)
    )
}

function Fill-Circle {
    param(
        [System.Drawing.Graphics]$Graphics,
        [System.Drawing.Brush]$Brush,
        [float]$Cx,
        [float]$Cy,
        [float]$Radius
    )

    $Graphics.FillEllipse($Brush, $Cx - $Radius, $Cy - $Radius, $Radius * 2.0, $Radius * 2.0)
}

function New-BerryKeepBitmap {
    param([int]$Size)

    $bitmap = New-Object System.Drawing.Bitmap $Size, $Size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.Clear([System.Drawing.Color]::Transparent)

    # Source geometry is authored in a 200x200 space (see docs/assets/ironmesh-favicon.svg).
    $scale = $Size / 200.0

    $panelPath = New-RoundedRectanglePath -X 0 -Y 0 -Width (200.0 * $scale) -Height (200.0 * $scale) -Radius (44.0 * $scale)
    $panelBrush = New-LinearBrush `
        -Start ([System.Drawing.PointF]::new(0, 0)) `
        -End ([System.Drawing.PointF]::new(200.0 * $scale, 200.0 * $scale)) `
        -StartColor "#7c3aed" -EndColor "#c026d3"
    $graphics.FillPath($panelBrush, $panelPath)

    # Leaf: two quadratic Beziers (converted to cubic) closed back to the start point.
    $leafP0 = [System.Drawing.PointF]::new(100.0 * $scale, 22.08 * $scale)
    $leafC1a = [System.Drawing.PointF]::new(117.6 * $scale, 11.52 * $scale)
    $leafC1b = [System.Drawing.PointF]::new(135.2 * $scale, 9.76 * $scale)
    $leafP1 = [System.Drawing.PointF]::new(152.8 * $scale, 16.8 * $scale)
    $leafC2a = [System.Drawing.PointF]::new(144.88 * $scale, 30.88 * $scale)
    $leafC2b = [System.Drawing.PointF]::new(131.68 * $scale, 37.92 * $scale)
    $leafP2 = [System.Drawing.PointF]::new(113.2 * $scale, 37.92 * $scale)

    $leafPath = New-Object System.Drawing.Drawing2D.GraphicsPath
    $leafPath.AddBezier($leafP0, $leafC1a, $leafC1b, $leafP1)
    $leafPath.AddBezier($leafP1, $leafC2a, $leafC2b, $leafP2)
    $leafPath.CloseFigure()

    $leafBrush = New-LinearBrush `
        -Start ([System.Drawing.PointF]::new(100.0 * $scale, 6.24 * $scale)) `
        -End ([System.Drawing.PointF]::new(152.8 * $scale, 37.92 * $scale)) `
        -StartColor "#86efac" -EndColor "#22c55e"
    $graphics.FillPath($leafBrush, $leafPath)

    $stemPen = New-Object System.Drawing.Pen(([System.Drawing.ColorTranslator]::FromHtml("#22c55e")), [Math]::Max(1.0, 6.6 * $scale))
    $stemPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $stemPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $graphics.DrawLine($stemPen, (100.0 * $scale), (35.28 * $scale), (100.0 * $scale), (53.76 * $scale))

    $branchPen = New-Object System.Drawing.Pen(([System.Drawing.Color]::FromArgb(217, 255, 255, 255)), [Math]::Max(1.0, 6.6 * $scale))
    $branchPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $branchPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round

    $top = [System.Drawing.PointF]::new(100.0 * $scale, 69.6 * $scale)
    $left = [System.Drawing.PointF]::new(57.76 * $scale, 109.2 * $scale)
    $right = [System.Drawing.PointF]::new(142.24 * $scale, 109.2 * $scale)
    $bottom = [System.Drawing.PointF]::new(100.0 * $scale, 162.0 * $scale)

    $graphics.DrawLine($branchPen, $top, $left)
    $graphics.DrawLine($branchPen, $top, $right)
    $graphics.DrawLine($branchPen, $left, $right)
    $graphics.DrawLine($branchPen, $left, $bottom)
    $graphics.DrawLine($branchPen, $right, $bottom)

    $berryBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
    $berryRadius = [Math]::Max(1.0, 18.48 * $scale)
    Fill-Circle -Graphics $graphics -Brush $berryBrush -Cx $top.X -Cy $top.Y -Radius $berryRadius
    Fill-Circle -Graphics $graphics -Brush $berryBrush -Cx $left.X -Cy $left.Y -Radius $berryRadius
    Fill-Circle -Graphics $graphics -Brush $berryBrush -Cx $right.X -Cy $right.Y -Radius $berryRadius
    Fill-Circle -Graphics $graphics -Brush $berryBrush -Cx $bottom.X -Cy $bottom.Y -Radius $berryRadius

    $highlightBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(191, 233, 213, 255))
    $highlightRadius = [Math]::Max(0.5, 5.016 * $scale)
    Fill-Circle -Graphics $graphics -Brush $highlightBrush -Cx (93.4 * $scale) -Cy (63.0 * $scale) -Radius $highlightRadius
    Fill-Circle -Graphics $graphics -Brush $highlightBrush -Cx (51.16 * $scale) -Cy (102.6 * $scale) -Radius $highlightRadius

    $stemPen.Dispose()
    $branchPen.Dispose()
    $berryBrush.Dispose()
    $highlightBrush.Dispose()
    $leafBrush.Dispose()
    $leafPath.Dispose()
    $panelBrush.Dispose()
    $panelPath.Dispose()
    $graphics.Dispose()

    return $bitmap
}

function Get-PngBytes {
    param([System.Drawing.Bitmap]$Bitmap)

    $stream = New-Object System.IO.MemoryStream
    try {
        $Bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
        return $stream.ToArray()
    }
    finally {
        $stream.Dispose()
    }
}

function Write-IcoFile {
    param(
        [string]$Path,
        [int[]]$Sizes,
        [byte[][]]$Images
    )

    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }

    $fileStream = [System.IO.File]::Create($Path)
    $writer = New-Object System.IO.BinaryWriter($fileStream)
    try {
        $count = $Images.Length
        $writer.Write([UInt16]0)
        $writer.Write([UInt16]1)
        $writer.Write([UInt16]$count)

        $offset = 6 + (16 * $count)
        for ($i = 0; $i -lt $count; $i++) {
            $size = $Sizes[$i]
            $png = $Images[$i]
            $writer.Write([byte]($(if ($size -ge 256) { 0 } else { $size })))
            $writer.Write([byte]($(if ($size -ge 256) { 0 } else { $size })))
            $writer.Write([byte]0)
            $writer.Write([byte]0)
            $writer.Write([UInt16]1)
            $writer.Write([UInt16]32)
            $writer.Write([UInt32]$png.Length)
            $writer.Write([UInt32]$offset)
            $offset += $png.Length
        }

        foreach ($png in $Images) {
            $writer.Write($png)
        }
    }
    finally {
        $writer.Dispose()
        $fileStream.Dispose()
    }
}

$sizes = @(16, 24, 32, 48, 64, 128, 256)
$images = @()

foreach ($size in $sizes) {
    $bitmap = New-BerryKeepBitmap -Size $size
    try {
        $images += ,(Get-PngBytes -Bitmap $bitmap)
    }
    finally {
        $bitmap.Dispose()
    }
}

$resolvedOutFile = (Resolve-Path (Split-Path -Parent $OutFile) -ErrorAction SilentlyContinue)
if (-not $resolvedOutFile) {
    $parent = Split-Path -Parent $OutFile
    if ($parent -and -not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent | Out-Null
    }
}

Write-IcoFile -Path $OutFile -Sizes $sizes -Images $images
Write-Output "Wrote $OutFile"
