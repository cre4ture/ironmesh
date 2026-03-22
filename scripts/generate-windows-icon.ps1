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

function New-ColorBlendBrush {
    param(
        [System.Drawing.PointF]$Start,
        [System.Drawing.PointF]$End,
        [string[]]$ColorHex,
        [float[]]$Positions
    )

    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $Start,
        $End,
        [System.Drawing.Color]::Black,
        [System.Drawing.Color]::White
    )
    $blend = New-Object System.Drawing.Drawing2D.ColorBlend
    $blend.Colors = $ColorHex | ForEach-Object { [System.Drawing.ColorTranslator]::FromHtml($_) }
    $blend.Positions = $Positions
    $brush.InterpolationColors = $blend
    return $brush
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

function New-IronmeshBitmap {
    param([int]$Size)

    $bitmap = New-Object System.Drawing.Bitmap $Size, $Size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.Clear([System.Drawing.Color]::Transparent)

    $scale = $Size / 256.0
    $rectX = 28.0 * $scale
    $rectY = 28.0 * $scale
    $rectSize = 200.0 * $scale
    $radius = 54.0 * $scale

    $panelPath = New-RoundedRectanglePath -X $rectX -Y $rectY -Width $rectSize -Height $rectSize -Radius $radius
    $panelBrush = New-ColorBlendBrush `
        -Start ([System.Drawing.PointF]::new(36.0 * $scale, 28.0 * $scale)) `
        -End ([System.Drawing.PointF]::new(214.0 * $scale, 228.0 * $scale)) `
        -ColorHex @("#112523", "#163f3a", "#0d6b5c") `
        -Positions @([float]0.0, [float]0.52, [float]1.0)
    $graphics.FillPath($panelBrush, $panelPath)

    $borderPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(46, 217, 255, 244)), (1.5 * $scale)
    $graphics.DrawPath($borderPen, $panelPath)

    $meshBrush = New-ColorBlendBrush `
        -Start ([System.Drawing.PointF]::new(72.0 * $scale, 68.0 * $scale)) `
        -End ([System.Drawing.PointF]::new(184.0 * $scale, 188.0 * $scale)) `
        -ColorHex @("#d9fff4", "#74e4c8", "#14b8a6") `
        -Positions @([float]0.0, [float]0.45, [float]1.0)
    $meshPen = New-Object System.Drawing.Pen($meshBrush, [Math]::Max(2.0, 10.0 * $scale))
    $meshPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $meshPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $meshPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round

    $nodes = @(
        [System.Drawing.PointF]::new(128.0 * $scale, 68.0 * $scale),
        [System.Drawing.PointF]::new(176.0 * $scale, 96.0 * $scale),
        [System.Drawing.PointF]::new(176.0 * $scale, 160.0 * $scale),
        [System.Drawing.PointF]::new(128.0 * $scale, 188.0 * $scale),
        [System.Drawing.PointF]::new(80.0 * $scale, 160.0 * $scale),
        [System.Drawing.PointF]::new(80.0 * $scale, 96.0 * $scale)
    )

    $graphics.DrawPolygon($meshPen, $nodes)
    $graphics.DrawLine($meshPen, $nodes[0], $nodes[3])
    $graphics.DrawLine($meshPen, $nodes[5], $nodes[2])
    $graphics.DrawLine($meshPen, $nodes[1], $nodes[4])
    $graphics.DrawLine($meshPen, $nodes[5], $nodes[1])
    $graphics.DrawLine($meshPen, $nodes[4], $nodes[2])

    $outerNodeBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.ColorTranslator]::FromHtml("#effff9"))
    $innerNodeBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.ColorTranslator]::FromHtml("#0d3d37"))
    $centerNodeBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.ColorTranslator]::FromHtml("#14b8a6"))
    $centerCoreBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.ColorTranslator]::FromHtml("#e9fff8"))

    $outerRadius = [Math]::Max(2.0, 10.0 * $scale)
    $innerRadius = [Math]::Max(1.0, 4.0 * $scale)
    foreach ($node in $nodes) {
        Fill-Circle -Graphics $graphics -Brush $outerNodeBrush -Cx $node.X -Cy $node.Y -Radius $outerRadius
        Fill-Circle -Graphics $graphics -Brush $innerNodeBrush -Cx $node.X -Cy $node.Y -Radius $innerRadius
    }

    $center = [System.Drawing.PointF]::new(128.0 * $scale, 128.0 * $scale)
    Fill-Circle -Graphics $graphics -Brush $centerNodeBrush -Cx $center.X -Cy $center.Y -Radius ([Math]::Max(2.5, 12.0 * $scale))
    Fill-Circle -Graphics $graphics -Brush $centerCoreBrush -Cx $center.X -Cy $center.Y -Radius ([Math]::Max(1.0, 4.0 * $scale))

    $meshPen.Dispose()
    $meshBrush.Dispose()
    $borderPen.Dispose()
    $panelBrush.Dispose()
    $panelPath.Dispose()
    $outerNodeBrush.Dispose()
    $innerNodeBrush.Dispose()
    $centerNodeBrush.Dispose()
    $centerCoreBrush.Dispose()
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
    $bitmap = New-IronmeshBitmap -Size $size
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
