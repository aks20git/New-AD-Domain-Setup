$inputpath = "C:\Files\Inputs"

$inputs = (Get-ChildItem -Path $inputpath).Name

foreach ($input in $inputs) {
    Start-Sleep -Seconds 3

    Write-Host "Reading file $inputPath\$input" -ForegroundColor Green
    .\RBACOUDelegation.ps1 -JSONPath "$inputPath\$input" -Remove $true
}