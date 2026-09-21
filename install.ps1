# jev-guard automated installer for Windows (PowerShell)
param (
    [switch]$Global,
    [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"

Write-Host "Installing jev-guard..." -ForegroundColor Cyan

$InstallDir = Join-Path $HOME ".jevguard\bin"
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$BinaryTarget = Join-Path $InstallDir "jev-guard.exe"

# If go is installed and source is available locally, build directly
if ((Get-Command go -ErrorAction SilentlyContinue) -and (Test-Path ".\main.go") -and (Test-Path ".\go.mod") -and ((Get-Content ".\go.mod" -Raw) -match '(?m)^module\s+jev-guard\b')) {
    Write-Host "Building jev-guard from local source with Go..." -ForegroundColor Yellow
    $GitCommit = try { (git rev-parse --short HEAD 2>$null).Trim() } catch { "none" }
    if (!$GitCommit) { $GitCommit = "none" }
    $GitDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $GitTag = try { (git describe --tags --exact-match 2>$null).Trim() } catch { "dev" }
    if (!$GitTag) { $GitTag = "dev" }
    $LdFlags = "-s -w -X jev-guard/pkg/cli.Version=$GitTag -X jev-guard/pkg/cli.Commit=$GitCommit -X jev-guard/pkg/cli.Date=$GitDate"
    go build -ldflags $LdFlags -o $BinaryTarget .\main.go
} else {
    if (![Environment]::Is64BitOperatingSystem) {
        Write-Error "Unsupported architecture: 32-bit Windows is not supported by prebuilt binaries. Please install Go and compile from source."
        exit 1
    }
    $Arch = "amd64"
    $Repo = if ($env:GITHUB_REPOSITORY) { $env:GITHUB_REPOSITORY } else { "ClemensSchartmueller/jev-guard" }
    $DownloadUrl = if ($Version -eq "latest") {
        "https://github.com/$Repo/releases/latest/download/jev-guard-windows-$Arch.exe"
    } else {
        "https://github.com/$Repo/releases/download/$Version/jev-guard-windows-$Arch.exe"
    }

    Write-Host "Downloading $DownloadUrl to $BinaryTarget..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $BinaryTarget
}

# Ensure .jevguard\bin is in User PATH
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "Adding $InstallDir to User PATH..." -ForegroundColor Green
    [Environment]::SetEnvironmentVariable("Path", "$InstallDir;$UserPath", "User")
    $env:Path = "$InstallDir;$env:Path"
}

Write-Host "jev-guard successfully installed at $BinaryTarget" -ForegroundColor Green
Write-Host "Run 'jev-guard --version' to verify." -ForegroundColor Cyan
