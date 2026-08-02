param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

$resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path

if (-not $resolvedPath.EndsWith('.wh.cpp', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The selected file is not a .wh.cpp Windhawk source file.'
}

$content = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop
Set-Clipboard -Value $content

Write-Host "Copied to clipboard: $resolvedPath" -ForegroundColor Green
