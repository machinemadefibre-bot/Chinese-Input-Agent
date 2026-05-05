$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")

function Read-RepoFile {
    param([string]$RelativePath)
    return Get-Content -LiteralPath (Join-Path $Root $RelativePath) -Raw -Encoding UTF8
}

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Test-PackagedModelNameIsWorkerDefault {
    $packageBat = Read-RepoFile "package-mingw.bat"
    $workerCpp = Read-RepoFile "tools\payload_watermark\cia_llama_worker.cpp"

    $packagedNames = @(
        [regex]::Matches($packageBat, 'models\\([^"\\]+\.gguf)"', "IgnoreCase") |
            ForEach-Object { $_.Groups[1].Value } |
            Sort-Object -Unique
    )
    $workerNamesMatch = [regex]::Match(
        $workerCpp,
        'const char \* names\[\] = \{(?<body>.*?)\};',
        "Singleline"
    )
    Assert-True $workerNamesMatch.Success "worker default model name list was not found"

    $workerNames = @(
        [regex]::Matches($workerNamesMatch.Groups["body"].Value, '"([^"]+\.gguf)"') |
            ForEach-Object { $_.Groups[1].Value } |
            Sort-Object -Unique
    )
    $overlap = @($packagedNames | Where-Object { $workerNames -contains $_ })
    Assert-True ($overlap.Count -gt 0) (
        "portable package writes GGUF names that the worker will not search for: " +
        "package=$($packagedNames -join ','), worker=$($workerNames -join ',')"
    )
}

function Test-DocsDoNotOverstateForwardSecrecy {
    $readmeCn = Read-RepoFile "README.md"
    $readmeEn = Read-RepoFile "README.en.md"

    Assert-True (-not $readmeCn.Contains("支持前向安全")) "Chinese README still claims forward secrecy support"
    Assert-True $readmeCn.Contains("Double Ratchet") "Chinese README should explain the forward secrecy boundary"
    Assert-True $readmeEn.Contains("full forward secrecy") "English README should explain the forward secrecy boundary"
    Assert-True $readmeEn.Contains("Double Ratchet-style forward secrecy is not implemented yet") "English README should avoid overstating the protocol"
}

function Test-WorkerResponseIdIsChecked {
    $appLlm = Read-RepoFile "src\app_llm.c"

    Assert-True $appLlm.Contains("response_id != id") "app_llm.c should reject mismatched worker response ids"
    Assert-True $appLlm.Contains("wrong request") "app_llm.c should emit a diagnostic for mismatched worker response ids"
}

$tests = @(
    "Test-PackagedModelNameIsWorkerDefault",
    "Test-DocsDoNotOverstateForwardSecrecy",
    "Test-WorkerResponseIdIsChecked"
)

foreach ($test in $tests) {
    & $test
    Write-Host "ok $test"
}
