# ======================================================================
# test-remediation.ps1 — End-to-End CSPM Test on LocalStack
# ======================================================================
# Usage: .\scripts\test-remediation.ps1
# Prerequisite: Run .\scripts\deploy-local.ps1 first
# ======================================================================

$ErrorActionPreference = "Stop"
$LOCALSTACK = "http://localhost:4566"
$REGION     = "us-east-1"

# Use the AWS CLI with LocalStack endpoint
$env:AWS_ACCESS_KEY_ID     = "test"
$env:AWS_SECRET_ACCESS_KEY = "test"
$env:AWS_DEFAULT_REGION    = $REGION

function Invoke-AWS {
    param([string]$Service, [string]$Args)
    $fullCmd = "aws --endpoint-url=$LOCALSTACK $Service $Args"
    Write-Host "  > $fullCmd" -ForegroundColor DarkGray
    $result = Invoke-Expression $fullCmd 2>&1
    return $result
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Serverless CSPM — End-to-End Test" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------------
# Step 1: Create a test S3 bucket with public access DISABLED
# ------------------------------------------------------------------
$TestBucket = "test-cspm-public-$(Get-Random -Maximum 99999)"
Write-Host "[1/6] Creating test bucket: $TestBucket ..." -ForegroundColor Yellow

$createResult = Invoke-AWS "s3api" "create-bucket --bucket $TestBucket --region $REGION"
Write-Host "       Bucket created." -ForegroundColor Green

# ------------------------------------------------------------------
# Step 2: Disable public access block (simulate misconfiguration)
# ------------------------------------------------------------------
Write-Host "[2/6] Disabling public access block (simulating misconfiguration) ..." -ForegroundColor Yellow

Invoke-AWS "s3api" "put-public-access-block --bucket $TestBucket --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
Write-Host "       Public access block DISABLED — bucket is vulnerable!" -ForegroundColor Red

# Verify it's open
$beforeConfig = Invoke-AWS "s3api" "get-public-access-block --bucket $TestBucket" | ConvertFrom-Json
Write-Host "       Before remediation:" -ForegroundColor DarkGray
Write-Host "         BlockPublicAcls:       $($beforeConfig.PublicAccessBlockConfiguration.BlockPublicAcls)" -ForegroundColor DarkGray
Write-Host "         IgnorePublicAcls:      $($beforeConfig.PublicAccessBlockConfiguration.IgnorePublicAcls)" -ForegroundColor DarkGray
Write-Host "         BlockPublicPolicy:     $($beforeConfig.PublicAccessBlockConfiguration.BlockPublicPolicy)" -ForegroundColor DarkGray
Write-Host "         RestrictPublicBuckets: $($beforeConfig.PublicAccessBlockConfiguration.RestrictPublicBuckets)" -ForegroundColor DarkGray

# ------------------------------------------------------------------
# Step 3: Build a mock CloudTrail event and invoke the Remediation Lambda
# ------------------------------------------------------------------
Write-Host "[3/6] Invoking Remediation Lambda with mock CloudTrail event ..." -ForegroundColor Yellow

$mockEvent = @{
    version       = "0"
    id            = [guid]::NewGuid().ToString()
    source        = "aws.s3"
    account       = "000000000000"
    region        = $REGION
    "detail-type" = "AWS API Call via CloudTrail"
    detail        = @{
        eventSource       = "s3.amazonaws.com"
        eventName         = "PutBucketPublicAccessBlock"
        recipientAccountId = "000000000000"
        awsRegion         = $REGION
        requestParameters = @{
            bucketName = $TestBucket
        }
    }
} | ConvertTo-Json -Depth 10 -Compress

# Write event to a temp file (aws cli reads from file)
$eventFile = [System.IO.Path]::GetTempFileName()
$mockEvent | Out-File -FilePath $eventFile -Encoding utf8

$lambdaResult = Invoke-AWS "lambda" "invoke --function-name cspm-s3-remediation-remediation --payload fileb://$eventFile --cli-binary-format raw-in-base64-out /tmp/lambda-response.json"
$lambdaResponse = Get-Content /tmp/lambda-response.json -Raw | ConvertFrom-Json
Write-Host "       Lambda response: $($lambdaResponse | ConvertTo-Json -Compress)" -ForegroundColor Green

Remove-Item $eventFile -Force -ErrorAction SilentlyContinue

# ------------------------------------------------------------------
# Step 4: Verify the bucket is now secure
# ------------------------------------------------------------------
Write-Host "[4/6] Checking if bucket was remediated ..." -ForegroundColor Yellow

$afterConfig = Invoke-AWS "s3api" "get-public-access-block --bucket $TestBucket" | ConvertFrom-Json
$pac = $afterConfig.PublicAccessBlockConfiguration

Write-Host "       After remediation:" -ForegroundColor DarkGray
Write-Host "         BlockPublicAcls:       $($pac.BlockPublicAcls)" -ForegroundColor DarkGray
Write-Host "         IgnorePublicAcls:      $($pac.IgnorePublicAcls)" -ForegroundColor DarkGray
Write-Host "         BlockPublicPolicy:     $($pac.BlockPublicPolicy)" -ForegroundColor DarkGray
Write-Host "         RestrictPublicBuckets: $($pac.RestrictPublicBuckets)" -ForegroundColor DarkGray

if ($pac.BlockPublicAcls -and $pac.IgnorePublicAcls -and $pac.BlockPublicPolicy -and $pac.RestrictPublicBuckets) {
    Write-Host "       PASS: All four flags are TRUE — bucket is secure!" -ForegroundColor Green
} else {
    Write-Host "       FAIL: Some flags are still FALSE — remediation did not work." -ForegroundColor Red
}

# ------------------------------------------------------------------
# Step 5: Check DynamoDB for the event log
# ------------------------------------------------------------------
Write-Host "[5/6] Querying DynamoDB for remediation event ..." -ForegroundColor Yellow

$scanResult = Invoke-AWS "dynamodb" "scan --table-name cspm-remediation-events"
$scanData = $scanResult | ConvertFrom-Json
$matchingEvents = $scanData.Items | Where-Object { $_.bucket_name.S -eq $TestBucket }

if ($matchingEvents) {
    Write-Host "       PASS: Found $($matchingEvents.Count) event(s) for bucket '$TestBucket' in DynamoDB." -ForegroundColor Green
    foreach ($evt in $matchingEvents) {
        Write-Host "         Status: $($evt.status.S) | Time: $($evt.timestamp.S)" -ForegroundColor DarkGray
    }
} else {
    Write-Host "       FAIL: No events found for '$TestBucket' in DynamoDB." -ForegroundColor Red
}

# ------------------------------------------------------------------
# Step 6: Test the API Lambda
# ------------------------------------------------------------------
Write-Host "[6/6] Invoking API Lambda (GET /events) ..." -ForegroundColor Yellow

$apiEvent = @{
    version        = "2.0"
    rawPath        = "/events"
    requestContext = @{
        http = @{
            method = "GET"
            path   = "/events"
        }
    }
} | ConvertTo-Json -Depth 10 -Compress

$apiEventFile = [System.IO.Path]::GetTempFileName()
$apiEvent | Out-File -FilePath $apiEventFile -Encoding utf8

$apiResult = Invoke-AWS "lambda" "invoke --function-name cspm-s3-remediation-api --payload fileb://$apiEventFile --cli-binary-format raw-in-base64-out /tmp/api-response.json"
$apiResponse = Get-Content /tmp/api-response.json -Raw | ConvertFrom-Json
$apiBody = $apiResponse.body | ConvertFrom-Json

Write-Host "       API returned $($apiBody.count) event(s)." -ForegroundColor Green

Remove-Item $apiEventFile -Force -ErrorAction SilentlyContinue

# ------------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Test Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Test bucket:      $TestBucket" -ForegroundColor White
Write-Host "  Remediated:       $(if ($pac.BlockPublicAcls) {'YES'} else {'NO'})" -ForegroundColor $(if ($pac.BlockPublicAcls) {'Green'} else {'Red'})
Write-Host "  DynamoDB logged:  $(if ($matchingEvents) {'YES'} else {'NO'})" -ForegroundColor $(if ($matchingEvents) {'Green'} else {'Red'})
Write-Host "  API working:      $(if ($apiBody.count -ge 0) {'YES'} else {'NO'})" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Cleanup test bucket
Write-Host "Cleaning up test bucket ..." -ForegroundColor DarkGray
Invoke-AWS "s3" "rb s3://$TestBucket --force" | Out-Null
Write-Host "Done." -ForegroundColor Green
