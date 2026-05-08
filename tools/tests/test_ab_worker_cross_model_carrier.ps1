param(
    [string]$AInstallDir = $env:CIA_TEST_A_INSTALL_DIR,
    [string]$BInstallDir = $env:CIA_TEST_B_INSTALL_DIR,
    [string]$WorkDir,
    [string]$AModelPath,
    [string]$BModelPath,
    [string]$ATokenizerId = "qwen3",
    [string]$BTokenizerId = "gemma4",
    [int]$PayloadLength = 48,
    [string]$MessageTopic = "daily life",
    [string]$KeyTopic = "job self introduction"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
if ([string]::IsNullOrWhiteSpace($AInstallDir)) {
    $AInstallDir = Join-Path $repoRoot "build\ab-installs\ChineseInputAgent-A"
}
if ([string]::IsNullOrWhiteSpace($BInstallDir)) {
    $BInstallDir = Join-Path $repoRoot "build\ab-installs\ChineseInputAgent-B"
}
if ([string]::IsNullOrWhiteSpace($WorkDir)) {
    $WorkDir = Join-Path $repoRoot "build\tests\ab_worker_cross_model"
}

function Write-Utf8NoBomFile([string]$Path, [string]$Text) {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $utf8NoBom)
}

function Resolve-WorkerExe {
    param(
        [Parameter(Mandatory = $true)][string]$InstallDir,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $candidates = @(
        (Join-Path $InstallDir "tools\payload_watermark\cia_llama_worker.exe"),
        (Join-Path $InstallDir "llama_worker_package\cia_llama_worker.exe")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "$Label worker not found under: $InstallDir"
}

function New-TestPayload([int]$Length, [byte]$FirstByte) {
    $payload = New-Object byte[] $Length
    for ($idx = 0; $idx -lt $Length; $idx++) {
        $payload[$idx] = [byte](($idx * 53 + 29) -band 0xff)
    }
    if ($Length -gt 0) {
        $payload[0] = $FirstByte
    }
    return $payload
}

function Read-JsonLine([string]$Line) {
    if (-not $Line) { return $null }
    try {
        return $Line | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Get-JsonProperty($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Resolve-TestModel {
    param(
        [string]$ConfiguredPath,
        [Parameter(Mandatory = $true)][string[]]$Patterns,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath)) {
        $resolved = Resolve-Path -LiteralPath $ConfiguredPath -ErrorAction SilentlyContinue
        if ($resolved) { return $resolved.Path }
        throw "$Label model not found: $ConfiguredPath"
    }

    foreach ($pattern in $Patterns) {
        $candidate = Get-ChildItem -LiteralPath (Join-Path $repoRoot "models") -Filter $pattern -ErrorAction SilentlyContinue |
            Sort-Object Name |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    throw "$Label model not found under $repoRoot\models"
}

function Read-U32Le([byte[]]$Bytes, [ref]$Offset) {
    if ($Offset.Value + 4 -gt $Bytes.Length) {
        throw "truncated u32"
    }
    $value = [uint32]$Bytes[$Offset.Value] -bor
        ([uint32]$Bytes[$Offset.Value + 1] -shl 8) -bor
        ([uint32]$Bytes[$Offset.Value + 2] -shl 16) -bor
        ([uint32]$Bytes[$Offset.Value + 3] -shl 24)
    $Offset.Value += 4
    return $value
}

function Test-DecodeMultiContainsPayload([string]$Path, [byte[]]$Payload) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $magic = [System.Text.Encoding]::ASCII.GetBytes("CIATKM1") + [byte]0
    if ($bytes.Length -lt 12) { throw "decode_multi candidate file is too short" }
    for ($idx = 0; $idx -lt $magic.Length; $idx++) {
        if ($bytes[$idx] -ne $magic[$idx]) { throw "decode_multi candidate file magic mismatch" }
    }
    [int]$offsetValue = 8
    $offset = [ref]$offsetValue
    $count = Read-U32Le $bytes $offset
    if ($count -lt 1) { throw "decode_multi returned no tokenizer candidates" }
    for ($candidateIdx = 0; $candidateIdx -lt $count; $candidateIdx++) {
        $tokenizerLen = Read-U32Le $bytes $offset
        if ($tokenizerLen -lt 1 -or $offset.Value + $tokenizerLen -gt $bytes.Length) {
            throw "decode_multi tokenizer id is invalid"
        }
        $offset.Value += $tokenizerLen
        $payloadLen = Read-U32Le $bytes $offset
        if ($offset.Value + $payloadLen -gt $bytes.Length) {
            throw "decode_multi payload is truncated"
        }
        if ($payloadLen -eq $Payload.Length) {
            $matches = $true
            for ($idx = 0; $idx -lt $Payload.Length; $idx++) {
                if ($bytes[$offset.Value + $idx] -ne $Payload[$idx]) {
                    $matches = $false
                    break
                }
            }
            if ($matches) { return }
        }
        $offset.Value += $payloadLen
    }
    throw "decode_multi did not return the expected payload"
}

function Invoke-WorkerRequests {
    param(
        [Parameter(Mandatory = $true)][string]$WorkerExe,
        [string]$WorkerArgs,
        [Parameter(Mandatory = $true)][string[]]$Requests,
        [Parameter(Mandatory = $true)][string]$StderrPath
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $WorkerExe
    $startInfo.Arguments = $WorkerArgs
    $startInfo.WorkingDirectory = Split-Path -Parent $WorkerExe
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    [void]$process.Start()

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    foreach ($request in $Requests) {
        $process.StandardInput.WriteLine($request)
    }
    $process.StandardInput.Close()
    $process.WaitForExit()

    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    $stdoutPath = [System.IO.Path]::ChangeExtension($StderrPath, ".stdout.log")
    if ($stdout) {
        Write-Utf8NoBomFile $stdoutPath $stdout
    }
    if ($stderr) {
        Write-Utf8NoBomFile $StderrPath $stderr
    }

    return [PSCustomObject]@{
        ExitCode = $process.ExitCode
        Stdout = $stdout
        StdoutPath = $stdoutPath
        StderrPath = $StderrPath
    }
}

function Assert-WorkerSucceeded {
    param(
        [Parameter(Mandatory = $true)]$Response,
        [Parameter(Mandatory = $true)][int]$ExpectedId,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Response.ExitCode -ne 0) {
        throw "$Label worker exited with code $($Response.ExitCode). stderr: $($Response.StderrPath)"
    }

    $ready = $false
    $done = $false
    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($line in ([System.Text.RegularExpressions.Regex]::Split($Response.Stdout.TrimEnd(), "`r?`n"))) {
        $message = Read-JsonLine $line
        if (-not $message) { continue }
        $messageType = Get-JsonProperty $message "type"
        $messageOk = Get-JsonProperty $message "ok"
        $messageId = Get-JsonProperty $message "id"
        $messageError = Get-JsonProperty $message "error"
        if ($messageType -eq "ready") {
            if ($messageOk -eq $true) {
                $ready = $true
            } else {
                $errors.Add("ready failed: $messageError")
            }
        } elseif ($messageType -eq "progress") {
            continue
        } elseif ($messageId -eq $ExpectedId -and $messageOk -eq $true) {
            $done = $true
        } elseif ($messageOk -eq $false) {
            $errors.Add("request $messageId failed: $messageError")
        }
    }

    if (-not $ready) {
        throw "$Label worker did not become ready. $($errors -join '; ') stderr: $($Response.StderrPath)"
    }
    if (-not $done) {
        throw "$Label request $ExpectedId did not succeed. $($errors -join '; ') stderr: $($Response.StderrPath)"
    }
}

function Invoke-CrossModelCarrierRoundTrip {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$EncodeWorkerExe,
        [Parameter(Mandatory = $true)][string]$EncodeWorkerArgs,
        [Parameter(Mandatory = $true)][string]$DecodeWorkerExe,
        [Parameter(Mandatory = $true)][string]$DecodeWorkerArgs,
        [Parameter(Mandatory = $true)][byte[]]$Payload,
        [Parameter(Mandatory = $true)][string]$Seed,
        [Parameter(Mandatory = $true)][string]$Topic
    )

    $caseDir = Join-Path $WorkDir $Name
    if (Test-Path -LiteralPath $caseDir) {
        Remove-Item -LiteralPath $caseDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $caseDir | Out-Null

    $payloadPath = Join-Path $caseDir "payload.bin"
    $topicPath = Join-Path $caseDir "topic.txt"
    $carrierPath = Join-Path $caseDir "carrier.txt"
    $decodedPath = Join-Path $caseDir "decoded.bin"

    [System.IO.File]::WriteAllBytes($payloadPath, $Payload)
    Write-Utf8NoBomFile $topicPath $Topic

    $encodeRequest = @{
        id = 1
        cmd = "encode"
        payload = $payloadPath
        out = $carrierPath
        topic_file = $topicPath
        seed = $Seed
    } | ConvertTo-Json -Compress
    $encodeShutdown = @{ id = 2; cmd = "shutdown" } | ConvertTo-Json -Compress
    $encodeResponse = Invoke-WorkerRequests -WorkerExe $EncodeWorkerExe -WorkerArgs $EncodeWorkerArgs -Requests @($encodeRequest, $encodeShutdown) `
        -StderrPath (Join-Path $caseDir "encode.stderr.log")
    Assert-WorkerSucceeded -Response $encodeResponse -ExpectedId 1 -Label "$Name encode"

    if (-not (Test-Path -LiteralPath $carrierPath -PathType Leaf)) {
        throw "$Name carrier text was not written"
    }

    $decodeRequest = @{
        id = 3
        cmd = "decode_multi"
        text = $carrierPath
        out = $decodedPath
        seed = $Seed
    } | ConvertTo-Json -Compress
    $decodeShutdown = @{ id = 4; cmd = "shutdown" } | ConvertTo-Json -Compress
    $decodeResponse = Invoke-WorkerRequests -WorkerExe $DecodeWorkerExe -WorkerArgs $DecodeWorkerArgs -Requests @($decodeRequest, $decodeShutdown) `
        -StderrPath (Join-Path $caseDir "decode.stderr.log")
    Assert-WorkerSucceeded -Response $decodeResponse -ExpectedId 3 -Label "$Name decode"

    if (-not (Test-Path -LiteralPath $decodedPath -PathType Leaf)) {
        throw "$Name decoded payload was not written"
    }

    Test-DecodeMultiContainsPayload $decodedPath $Payload

    $carrierChars = (Get-Content -LiteralPath $carrierPath -Raw -Encoding UTF8).Length
    Write-Host "ok Test-$Name payload=$($Payload.Length) carrier_chars=$carrierChars"
}

$aWorker = Resolve-WorkerExe -InstallDir $AInstallDir -Label "A"
$bWorker = Resolve-WorkerExe -InstallDir $BInstallDir -Label "B"
$AModelPath = Resolve-TestModel -ConfiguredPath $AModelPath -Patterns @("Qwen3-0.6B-*.gguf", "Qwen3-*.gguf") -Label "A"
$BModelPath = Resolve-TestModel -ConfiguredPath $BModelPath -Patterns @("gemma-4*.gguf", "gemma*.gguf") -Label "B"
$aArgs = "--model `"$AModelPath`" --tokenizer-id $ATokenizerId"
$bArgs = "--model `"$BModelPath`" --tokenizer-id $BTokenizerId"

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

Write-Host "A install: $AInstallDir"
Write-Host "B install: $BInstallDir"
Write-Host "A worker: $aWorker"
Write-Host "B worker: $bWorker"
Write-Host "A model: $AModelPath tokenizer=$ATokenizerId"
Write-Host "B model: $BModelPath tokenizer=$BTokenizerId"

$messageSeed = "ChineseInputAgent top-k payload seed v1:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
$keySeed = "ChineseInputAgent key-exchange top-k payload v1"
$topic = $MessageTopic

Invoke-CrossModelCarrierRoundTrip `
    -Name "ABCrossModelMessageCarrier_AEncode_BDecode" `
    -EncodeWorkerExe $aWorker `
    -EncodeWorkerArgs $aArgs `
    -DecodeWorkerExe $bWorker `
    -DecodeWorkerArgs $bArgs `
    -Payload (New-TestPayload $PayloadLength 0x21) `
    -Seed $messageSeed `
    -Topic $topic

Invoke-CrossModelCarrierRoundTrip `
    -Name "ABCrossModelMessageCarrier_BEncode_ADecode" `
    -EncodeWorkerExe $bWorker `
    -EncodeWorkerArgs $bArgs `
    -DecodeWorkerExe $aWorker `
    -DecodeWorkerArgs $aArgs `
    -Payload (New-TestPayload $PayloadLength 0x21) `
    -Seed $messageSeed `
    -Topic $topic

Invoke-CrossModelCarrierRoundTrip `
    -Name "ABCrossModelKeyCarrier_AEncode_BDecode" `
    -EncodeWorkerExe $aWorker `
    -EncodeWorkerArgs $aArgs `
    -DecodeWorkerExe $bWorker `
    -DecodeWorkerArgs $bArgs `
    -Payload (New-TestPayload 57 0x51) `
    -Seed $keySeed `
    -Topic $KeyTopic

Invoke-CrossModelCarrierRoundTrip `
    -Name "ABCrossModelKeyCarrier_BEncode_ADecode" `
    -EncodeWorkerExe $bWorker `
    -EncodeWorkerArgs $bArgs `
    -DecodeWorkerExe $aWorker `
    -DecodeWorkerArgs $aArgs `
    -Payload (New-TestPayload 57 0x51) `
    -Seed $keySeed `
    -Topic $KeyTopic
