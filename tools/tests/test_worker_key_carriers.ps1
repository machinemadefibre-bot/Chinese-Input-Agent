param(
    [string]$WorkerExe,
    [string]$WorkDir,
    [string]$ModelPath,
    [switch]$FullLength
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
if (-not $WorkerExe) {
    $WorkerExe = Join-Path $repoRoot "build\llama_worker_package\cia_llama_worker.exe"
}
if (-not $WorkDir) {
    $WorkDir = Join-Path $repoRoot "build\tests\worker_key_carriers"
}

function Write-Utf8NoBomFile([string]$Path, [string]$Text) {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $utf8NoBom)
}

function New-TextFromCodePoints([int[]]$CodePoints) {
    $builder = New-Object System.Text.StringBuilder
    foreach ($codePoint in $CodePoints) {
        [void]$builder.Append([char]$codePoint)
    }
    return $builder.ToString()
}

function New-TestPayload([int]$Length, [byte]$FirstByte) {
    $payload = New-Object byte[] $Length
    for ($i = 0; $i -lt $Length; $i++) {
        $payload[$i] = [byte](($i * 37 + 17) -band 0xff)
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
    for ($i = 0; $i -lt $magic.Length; $i++) {
        if ($bytes[$i] -ne $magic[$i]) { throw "decode_multi candidate file magic mismatch" }
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
            for ($i = 0; $i -lt $Payload.Length; $i++) {
                if ($bytes[$offset.Value + $i] -ne $Payload[$i]) {
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
        [string[]]$Requests,
        [string]$StderrPath
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $WorkerExe
    $startInfo.WorkingDirectory = Split-Path -Parent $WorkerExe
    if ($ModelPath) {
        $startInfo.Arguments = '--model "' + $ModelPath.Replace('"', '\"') + '"'
    }
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
    if ($stderr) {
        Write-Utf8NoBomFile $StderrPath $stderr
    }

    return [PSCustomObject]@{
        ExitCode = $process.ExitCode
        Stdout = $stdout
        StderrPath = $StderrPath
    }
}

function Invoke-WorkerCarrierRoundTrip {
    param(
        [string]$Name,
        [byte[]]$Payload,
        [string]$Topic,
        [string]$PromptTemplate,
        [string]$Prefix
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
    $decodedMultiPath = Join-Path $caseDir "decoded_multi.bin"
    $outlinePath = Join-Path $caseDir "outline.txt"

    [System.IO.File]::WriteAllBytes($payloadPath, $Payload)
    Write-Utf8NoBomFile $topicPath $Topic

    $seed = "ChineseInputAgent key-exchange top-k payload v1"
    $encodeRequest = @{
        id = 1
        cmd = "encode"
        payload = $payloadPath
        out = $carrierPath
        outline_out = $outlinePath
        topic_file = $topicPath
        seed = $seed
        prompt_template = $PromptTemplate
    } | ConvertTo-Json -Compress

    $decodeRequest = @{
        id = 2
        cmd = "decode"
        text = $carrierPath
        out = $decodedPath
        seed = $seed
    } | ConvertTo-Json -Compress

    $decodeMultiRequest = @{
        id = 3
        cmd = "decode_multi"
        text = $carrierPath
        out = $decodedMultiPath
        seed = $seed
    } | ConvertTo-Json -Compress

    $shutdownRequest = @{ id = 4; cmd = "shutdown" } | ConvertTo-Json -Compress

    $stderrPath = Join-Path $caseDir "worker.stderr.log"
    $response = Invoke-WorkerRequests -Requests @($encodeRequest, $decodeRequest, $decodeMultiRequest, $shutdownRequest) -StderrPath $stderrPath
    if ($response.ExitCode -ne 0) {
        throw "$Name worker exited with code $($response.ExitCode). stderr: $stderrPath"
    }

    $ready = $false
    $encoded = $false
    $decoded = $false
    $decodedMulti = $false
    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($line in ([System.Text.RegularExpressions.Regex]::Split($response.Stdout.TrimEnd(), "`r?`n"))) {
        $message = Read-JsonLine $line
        if (-not $message) { continue }
        if ($message.type -eq "ready") {
            if ($message.ok -eq $true) {
                $ready = $true
            } else {
                $errors.Add("ready failed: $($message.error)")
            }
        } elseif ($message.type -eq "progress") {
            continue
        } elseif ($message.id -eq 1 -and $message.ok -eq $true) {
            $encoded = $true
        } elseif ($message.id -eq 2 -and $message.ok -eq $true) {
            $decoded = $true
        } elseif ($message.id -eq 3 -and $message.ok -eq $true) {
            $decodedMulti = $true
        } elseif ($message.ok -eq $false) {
            if ($message.id -eq 2 -and -not $encoded -and -not (Test-Path -LiteralPath $carrierPath -PathType Leaf)) {
                continue
            }
            $errors.Add("request $($message.id) failed: $($message.error)")
        }
    }

    if (-not $ready) {
        throw "$Name worker did not report ready. $($errors -join '; ') stderr: $stderrPath"
    }
    if (-not $encoded) {
        throw "$Name encode did not succeed. $($errors -join '; ') stderr: $stderrPath"
    }
    if (-not $decoded) {
        throw "$Name decode did not succeed. $($errors -join '; ') stderr: $stderrPath"
    }
    if (-not $decodedMulti) {
        throw "$Name decode_multi did not succeed. $($errors -join '; ') stderr: $stderrPath"
    }
    if (-not (Test-Path -LiteralPath $carrierPath -PathType Leaf)) {
        throw "$Name carrier text was not written"
    }
    if (-not (Test-Path -LiteralPath $outlinePath -PathType Leaf)) {
        throw "$Name outline text was not written"
    }
    if (-not (Test-Path -LiteralPath $decodedPath -PathType Leaf)) {
        throw "$Name decoded payload was not written"
    }
    if (-not (Test-Path -LiteralPath $decodedMultiPath -PathType Leaf)) {
        throw "$Name decode_multi candidate file was not written"
    }

    $carrierBody = Get-Content -LiteralPath $carrierPath -Raw -Encoding UTF8
    $outlineBody = Get-Content -LiteralPath $outlinePath -Raw -Encoding UTF8
    if ($null -ne $outlineBody -and $outlineBody.Trim()) {
        $outlineWasWritten = $true
    }
    $carrier = $Prefix + $carrierBody
    if (-not $carrier.StartsWith($Prefix)) {
        throw "$Name carrier prefix mismatch"
    }

    $decodedBytes = [System.IO.File]::ReadAllBytes($decodedPath)
    if ($decodedBytes.Length -ne $Payload.Length) {
        throw "$Name decoded payload length mismatch"
    }
    for ($i = 0; $i -lt $Payload.Length; $i++) {
        if ($decodedBytes[$i] -ne $Payload[$i]) {
            throw "$Name decoded payload byte mismatch at $i"
        }
    }
    Test-DecodeMultiContainsPayload $decodedMultiPath $Payload

    Write-Host "ok Test-$Name"
}

if (-not (Test-Path -LiteralPath $WorkerExe -PathType Leaf)) {
    Write-Host "skip Test-WorkerKeyCarriers: worker exe not found at $WorkerExe"
    exit 0
}
if ($ModelPath) {
    $resolvedModel = Resolve-Path -LiteralPath $ModelPath -ErrorAction SilentlyContinue
    if (-not $resolvedModel) {
        throw "ModelPath does not exist: $ModelPath"
    }
    $ModelPath = $resolvedModel.Path
} else {
    $workerDir = Split-Path -Parent $WorkerExe
    $configPath = Join-Path $workerDir "worker_config.txt"
    $configuredModel = "base_model.gguf"
    if (Test-Path -LiteralPath $configPath -PathType Leaf) {
        $modelLine = Get-Content -LiteralPath $configPath -Encoding UTF8 |
            Where-Object { $_ -match '^\s*model\s*=\s*(.+?)\s*$' } |
            Select-Object -First 1
        if ($modelLine -and $modelLine -match '^\s*model\s*=\s*(.+?)\s*$') {
            $configuredModel = $Matches[1]
        }
    }
    $candidateModels = @(
        (Join-Path $workerDir $configuredModel),
        (Join-Path $workerDir "models\$configuredModel"),
        (Join-Path $workerDir "..\models\$configuredModel"),
        (Join-Path $workerDir "..\..\models\$configuredModel"),
        (Join-Path $repoRoot "models\$configuredModel")
    )
    $hasConfiguredModel = $false
    foreach ($candidate in $candidateModels) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $hasConfiguredModel = $true
            break
        }
    }
    if (-not $hasConfiguredModel) {
        Write-Host "skip Test-WorkerKeyCarriers: configured model not found ($configuredModel)"
        exit 0
    }
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

$selfIntroTopic = New-TextFromCodePoints @(0x6c42,0x804c,0x81ea,0x6211,0x4ecb,0x7ecd)
$contactPrefix = (New-TextFromCodePoints @(0x4f60,0x597d,0xff0c,0x6211,0x662f,0x7f16,0x53f7)) +
    "ABCDEFGH" +
    (New-TextFromCodePoints @(0xff0c,0x8fd9,0x662f,0x6211,0x7684,0x81ea,0x6211,0x4ecb,0x7ecd,0x3002))
$groupTopic = New-TextFromCodePoints @(0x793e,0x56e2,0x62db,0x65b0,0x7b80,0x4ecb,0x3001,0x793e,0x56e2,0x4ecb,0x7ecd)
$groupPrefix = (New-TextFromCodePoints @(0x4f60,0x597d,0xff01,0x6211,0x4eec,0x7684,0x793e,0x56e2,0x7f16,0x53f7,0x662f)) +
    "ABCDEFGH" +
    (New-TextFromCodePoints @(0x3002,0x8fd9,0x662f,0x6211,0x4eec,0x793e,0x56e2,0x7684,0x4ecb,0x7ecd,0x3002))

$contactPayloadLength = if ($FullLength) { 105 } else { 32 }
$groupPayloadLength = if ($FullLength) { 57 } else { 32 }

Invoke-WorkerCarrierRoundTrip `
    -Name "ExportPersonalKeyCarrier" `
    -Payload (New-TestPayload $contactPayloadLength 0x21) `
    -Topic $selfIntroTopic `
    -PromptTemplate "self_intro" `
    -Prefix $contactPrefix

Invoke-WorkerCarrierRoundTrip `
    -Name "CreateGroupKeyCarrier" `
    -Payload (New-TestPayload $groupPayloadLength 0x51) `
    -Topic $groupTopic `
    -PromptTemplate "group_key" `
    -Prefix $groupPrefix
