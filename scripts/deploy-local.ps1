# ======================================================================
# deploy-local.ps1 — Deploy Serverless CSPM to LocalStack
# ======================================================================
# Usage: .\scripts\deploy-local.ps1
# Prerequisites: Docker Desktop running
# ======================================================================

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Serverless CSPM — LocalStack Deployment" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------------
# Step 1: Start LocalStack
# ------------------------------------------------------------------
Write-Host "[1/4] Starting LocalStack via Docker Compose ..." -ForegroundColor Yellow
Push-Location $ProjectRoot
try {
    docker-compose up -d
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: docker-compose failed. Is Docker Desktop running?" -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}

# ------------------------------------------------------------------
# Step 2: Wait for LocalStack to be healthy
# ------------------------------------------------------------------
Write-Host "[2/4] Waiting for LocalStack to become healthy ..." -ForegroundColor Yellow
$maxAttempts = 30
$attempt = 0
$healthy = $false

while ($attempt -lt $maxAttempts) {
    $attempt++
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:4566/_localstack/health" -TimeoutSec 3 -ErrorAction Stop
        if ($response.services) {
            $healthy = $true
            Write-Host "       LocalStack is ready! (attempt $attempt)" -ForegroundColor Green
            break
        }
    } catch {
        Write-Host "       Waiting ... (attempt $attempt/$maxAttempts)" -ForegroundColor DarkGray
    }
    Start-Sleep -Seconds 2
}

if (-not $healthy) {
    Write-Host "ERROR: LocalStack did not become healthy after $maxAttempts attempts." -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------------
# Step 3: Terraform Init
# ------------------------------------------------------------------
Write-Host "[3/4] Running terraform init ..." -ForegroundColor Yellow
Push-Location "$ProjectRoot\terraform"
try {
    terraform init -input=false
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: terraform init failed." -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}

# ------------------------------------------------------------------
# Step 4: Terraform Apply
# ------------------------------------------------------------------
Write-Host "[4/4] Running terraform apply with LocalStack overrides ..." -ForegroundColor Yellow
Push-Location "$ProjectRoot\terraform"
try {
    terraform apply -var-file=localstack.tfvars -auto-approve -input=false
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: terraform apply failed." -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Deployment complete!" -ForegroundColor Green
Write-Host "  All AWS resources are running on LocalStack (localhost:4566)" -ForegroundColor Green
Write-Host "" -ForegroundColor Green
Write-Host "  Next: Run .\scripts\test-remediation.ps1 to test the pipeline" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
