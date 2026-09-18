# jev-guard automated installer for Windows (PowerShell)
param (
    [switch]$Global,
    [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"

Write-Host "Installing jev-guard..." -ForegroundColor Cyan

$InstallDir = Join-Path $HOME ".local\bin"
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$BinaryTarget = Join-Path $InstallDir "jev-guard.exe"

# If go is installed and source is available locally, build directly
if (Get-Command go -ErrorAction SilentlyContinue -and (Test-Path ".\main.go")) {
    Write-Host "Building jev-guard from local source with Go..." -ForegroundColor Yellow
    go build -ldflags="-s -w" -o $BinaryTarget .\main.go
} else {
    $Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    $Repo = "typesafe-ai/jev-guard"
    $DownloadUrl = if ($Version -eq "latest") {
        "https://github.com/$Repo/releases/latest/download/jev-guard-windows-$Arch.exe"
    } else {
        "https://github.com/$Repo/releases/download/$Version/jev-guard-windows-$Arch.exe"
    }

    Write-Host "Downloading $DownloadUrl to $BinaryTarget..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $BinaryTarget
}

# Ensure .local\bin is in User PATH
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "Adding $InstallDir to User PATH..." -ForegroundColor Green
    [Environment]::SetEnvironmentVariable("Path", "$InstallDir;$UserPath", "User")
    $env:Path = "$InstallDir;$env:Path"
}

Write-Host "jev-guard successfully installed at $BinaryTarget" -ForegroundColor Green
Write-Host "Run 'jev-guard --version' to verify." -ForegroundColor Cyan
