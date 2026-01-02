<#
URL Forwarder Manager - Docker Build/Test/Push (PowerShell)

Usage:
  .\scripts\build-and-deploy.ps1                       # Build only
  .\scripts\build-and-deploy.ps1 -Test                 # Build + run quick smoke test locally
  .\scripts\build-and-deploy.ps1 -Push                 # Build + push to GHCR
  .\scripts\build-and-deploy.ps1 -Test -Push           # Full pipeline

Auth for GHCR:
  Set either $env:GHCR_TOKEN or $env:GITHUB_TOKEN (recommended).
  This script will NOT store tokens in the repo.

Examples:
  $env:GHCR_TOKEN = "<your_token_here>"
  .\scripts\build-and-deploy.ps1 -GitHubUsername yourname -Push
#>

param(
    [string]$RegistryUrl = "ghcr.io",
    [Parameter(Mandatory = $true)]
    [string]$GitHubUsername,
    [string]$RepoName = "",
    [string]$Version = "",
    [string]$DockerfilePath = "Dockerfile",
    [switch]$Test,
    [switch]$Push,
    [switch]$SkipPrune
)

function Write-Title($msg) { Write-Host $msg -ForegroundColor Cyan }
function Write-Success($msg) { Write-Host $msg -ForegroundColor Green }
function Write-Warn($msg) { Write-Host $msg -ForegroundColor Yellow }
function Write-Err($msg) { Write-Host $msg -ForegroundColor Red }
function Write-Info($msg) { Write-Host $msg -ForegroundColor White }

function Get-DefaultRepoName {
    return (Split-Path -Leaf (Get-Location)).ToLower()
}

function Get-Version {
    param([string]$Provided)
    if ($Provided) { return $Provided }

    # Prefer git tag/describe when available, otherwise date-based.
    try {
        $git = (git describe --tags --always 2>$null)
        if ($LASTEXITCODE -eq 0 -and $git) {
            return ($git.Trim() -replace '[^a-zA-Z0-9._-]', '-')
        }
    } catch {}

    return (Get-Date -Format "0.1.0-yyyyMMdd-HHmm")
}

function Get-GhcrToken {
    # Optional local-only secrets file (gitignored). Put your token there once.
    # Expected content example:
    #   $env:GHCR_TOKEN = "ghp_..."
    try {
        $secretsPath = Join-Path $PSScriptRoot "_secrets.ps1"
        if (Test-Path $secretsPath) {
            . $secretsPath
        }
    } catch {}

    if ($env:GHCR_TOKEN) { return $env:GHCR_TOKEN }
    if ($env:GITHUB_TOKEN) { return $env:GITHUB_TOKEN }

    # Optional: use GitHub CLI token if installed and logged in.
    try {
        $gh = (Get-Command gh -ErrorAction SilentlyContinue)
        if ($gh) {
            $t = (gh auth token 2>$null)
            if ($t) { return $t.Trim() }
        }
    } catch {}

    return ""
}

function Ensure-DockerRunning {
    $dockerCheck = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is not running. Please start Docker Desktop and try again."
    }
}

function Docker-LoginGhcr {
    param(
        [string]$Registry,
        [string]$Username
    )
    $token = Get-GhcrToken
    if (-not $token) {
        throw "No GHCR token found. Set `$env:GHCR_TOKEN (or `$env:GITHUB_TOKEN) and retry."
    }

    Write-Info "  Logging into $Registry as $Username..."
    Write-Output $token | docker login $Registry -u $Username --password-stdin
    if ($LASTEXITCODE -ne 0) {
        throw "Docker login failed. Ensure your token has packages scopes (read/write)."
    }
    Write-Success "  [OK] Logged in"
}

function Docker-SmokeTest {
    param(
        [string]$ImageTag
    )

    Write-Title "Smoke test: starting container..."

    $name = "redirector-test"
    docker stop $name 2>$null | Out-Null
    docker rm $name 2>$null | Out-Null

    $dataDir = Join-Path (Get-Location) "data"
    if (-not (Test-Path $dataDir)) {
        New-Item -ItemType Directory -Path $dataDir | Out-Null
    }

    docker run --rm -d --name $name -p 8000:8000 `
        -e ADMIN_USER=admin `
        -e ADMIN_PASS=admin `
        -v "${dataDir}:/app/data" `
        $ImageTag | Out-Null

    Start-Sleep -Seconds 2

    $running = docker ps -q -f "name=$name"
    if (-not $running) {
        Write-Err "  Container failed to start. Logs:"
        docker logs $name 2>&1
        throw "Smoke test failed: container not running."
    }

    # Expect 401 on /admin without credentials.
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:8000/admin" -UseBasicParsing -TimeoutSec 10
        # If we got here, it wasn't 401 (unexpected)
        Write-Warn "  Unexpected response: $($resp.StatusCode)"
        throw "Smoke test failed: /admin did not require auth."
    } catch {
        # PowerShell throws for non-2xx; that's expected here.
        $msg = $_.Exception.Message
        if ($msg -notmatch "401") {
            Write-Warn "  /admin check threw: $msg"
        } else {
            Write-Success "  [OK] /admin requires auth (401)"
        }
    }

    # Expect 404 on root when no rules exist.
    try {
        $resp2 = Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing -TimeoutSec 10
        Write-Warn "  Unexpected 2xx on /: $($resp2.StatusCode)"
    } catch {
        $msg2 = $_.Exception.Message
        if ($msg2 -match "404") {
            Write-Success "  [OK] / returns 404 when no rules match"
        } else {
            Write-Warn "  / check threw: $msg2"
        }
    }

    docker stop $name | Out-Null
    Write-Success "  [OK] Smoke test complete"
}

try {
    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Magenta
    Write-Host "   Redirector - Docker Build / Test / Push (GHCR)        " -ForegroundColor Magenta
    Write-Host "=========================================================" -ForegroundColor Magenta
    Write-Host ""

    Ensure-DockerRunning

    # Defensive trimming to prevent invalid docker references (e.g. accidental leading/trailing spaces).
    # NOTE: Use PS5.1-safe coercion ("" + $null => "") instead of `??`.
    $RegistryUrl = ("" + $RegistryUrl).Trim()
    $GitHubUsername = ("" + $GitHubUsername).Trim()
    $RepoName = ("" + $RepoName).Trim()
    $DockerfilePath = ("" + $DockerfilePath).Trim()
    $Version = ("" + $Version).Trim()

    if (-not $RepoName) { $RepoName = Get-DefaultRepoName }
    $Version = Get-Version -Provided $Version

    $app = $RepoName.ToLower()
    $imageTag = "$RegistryUrl/$($GitHubUsername.ToLower())/$app`:$Version"
    $latestTag = "$RegistryUrl/$($GitHubUsername.ToLower())/$app`:latest"

    Write-Title "Configuration:"
    Write-Info "  Registry:        $RegistryUrl"
    Write-Info "  GitHub Username: $GitHubUsername"
    Write-Info "  Repo/Image:      $app"
    Write-Info "  Version:         $Version"
    Write-Info "  Dockerfile:      $DockerfilePath"
    Write-Info "  Tag:             $imageTag"
    Write-Info "  Tag (latest):    $latestTag"
    Write-Host ""

    if (-not $SkipPrune) {
        Write-Title "Step 1: Cleaning up..."
        docker system prune -f 2>$null | Out-Null
        Write-Success "  [OK] Cleanup complete"
        Write-Host ""
    }

    Write-Title "Step 2: Building Docker image..."
    $buildStart = Get-Date
    docker build -t $imageTag -t $latestTag -f $DockerfilePath .
    if ($LASTEXITCODE -ne 0) { throw "Docker build failed." }
    $buildTime = (Get-Date) - $buildStart
    Write-Success "  [OK] Build complete in $([math]::Round($buildTime.TotalSeconds, 1))s"

    if ($Test) {
        Write-Host ""
        Write-Title "Step 3: Testing locally..."
        Docker-SmokeTest -ImageTag $imageTag
    }

    if ($Push) {
        Write-Host ""
        Write-Title "Step 4: Pushing to GHCR..."
        Docker-LoginGhcr -Registry $RegistryUrl -Username $GitHubUsername

        Write-Info "  Pushing $imageTag..."
        docker push $imageTag
        if ($LASTEXITCODE -ne 0) { throw "Push failed for $imageTag" }

        Write-Info "  Pushing $latestTag..."
        docker push $latestTag
        if ($LASTEXITCODE -ne 0) { throw "Push failed for $latestTag" }

        Write-Success "  [OK] Images pushed"
    }

    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Green
    Write-Success "DONE"
    Write-Host "=========================================================" -ForegroundColor Green
    Write-Host ""

    if ($Push) {
        Write-Title "Deploy on Coolify:"
        Write-Info "  Use Docker Image: $latestTag"
        Write-Info "  Mount volume to:  /app/data"
        Write-Info "  Set env vars:     ADMIN_USER, ADMIN_PASS (and optional PORT/DB_PATH)"
        Write-Host ""
    }

} catch {
    Write-Host ""
    Write-Err "========================================================="
    Write-Err "FAILED"
    Write-Err "========================================================="
    Write-Err "Error: $($_.Exception.Message)"
    Write-Host ""
    exit 1
}


