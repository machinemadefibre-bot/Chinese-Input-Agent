param(
    [string]$WorkerExe,
    [string]$OutDir,
    [string]$ModelDir,
    [string[]]$ModelId,
    [int]$SamplesPerPrompt = 3,
    [int]$MaxFixRetries = 3,
    [switch]$NoDownload
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $repoRoot "build\tests\openbmb_writing_eval"
}
if ([string]::IsNullOrWhiteSpace($ModelDir)) {
    $ModelDir = Join-Path $OutDir "models"
}
if ([string]::IsNullOrWhiteSpace($WorkerExe)) {
    foreach ($candidate in @(
        (Join-Path $repoRoot "build\llama_worker_cpu\cia_llama_worker.exe"),
        (Join-Path $repoRoot "build\llama_worker_package\cia_llama_worker.exe"),
        (Join-Path $repoRoot "build\llama_worker_vulkan\cia_llama_worker.exe")
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $WorkerExe = (Resolve-Path -LiteralPath $candidate).Path
            break
        }
    }
}
if (-not (Test-Path -LiteralPath $WorkerExe -PathType Leaf)) {
    throw "Worker exe not found. Build llama worker first or pass -WorkerExe."
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $ModelDir | Out-Null
$sampleDir = Join-Path $OutDir "samples"
$promptRoot = Join-Path $OutDir "prompt_profiles"
New-Item -ItemType Directory -Force -Path $sampleDir | Out-Null
New-Item -ItemType Directory -Force -Path $promptRoot | Out-Null

function Read-Utf8File([string]$Path) {
    return [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($Path))
}

function Write-Utf8NoBomFile([string]$Path, [string]$Text) {
    $dir = Split-Path -Parent $Path
    if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $utf8)
}

function New-TextFromCodePoints([int[]]$CodePoints) {
    $builder = New-Object System.Text.StringBuilder
    foreach ($codePoint in $CodePoints) {
        [void]$builder.Append([System.Char]::ConvertFromUtf32($codePoint))
    }
    return $builder.ToString()
}

function Read-WorkerConfig {
    $config = @{}
    $path = Join-Path $repoRoot "tools\payload_watermark\worker_config.txt"
    foreach ($line in Get-Content -LiteralPath $path -Encoding UTF8) {
        if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
        $parts = $line.Split("=", 2)
        $config[$parts[0].Trim()] = $parts[1].Trim()
    }
    return $config
}

function Resolve-LocalModel([string[]]$Patterns, [string]$Label) {
    foreach ($pattern in $Patterns) {
        $candidate = Get-ChildItem -LiteralPath (Join-Path $repoRoot "models") -Filter $pattern -ErrorAction SilentlyContinue |
            Sort-Object Name |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    throw "$Label model not found under $repoRoot\models"
}

function Get-SafeName([string]$Text) {
    return ($Text -replace '[^A-Za-z0-9_.-]', '_')
}

function Get-HfTree([string]$Repo) {
    $url = "https://huggingface.co/api/models/$Repo/tree/main?recursive=1"
    return @(Invoke-RestMethod -Uri $url -UseBasicParsing)
}

function Select-GgufFile($Files, [string[]]$QuantPreference) {
    $ggufs = @($Files | Where-Object {
        $_.type -eq "file" -and
        ([string]$_.path).ToLowerInvariant().EndsWith(".gguf") -and
        ([string]$_.path) -notmatch '(?i)(mmproj|projector|vision|encoder)'
    })
    foreach ($quant in $QuantPreference) {
        $match = $ggufs | Where-Object {
            $leaf = (([string]$_.path) -replace '^.*/','')
            $leaf -match [regex]::Escape($quant)
        } | Sort-Object path | Select-Object -First 1
        if ($match) { return $match }
    }
    return ($ggufs | Sort-Object path | Select-Object -First 1)
}

function Download-HfFile($File, [string]$Repo, [string]$Destination) {
    if (Test-Path -LiteralPath $Destination -PathType Leaf) {
        if ($File.lfs -and $File.lfs.oid) {
            $expectedExisting = ([string]$File.lfs.oid).ToLowerInvariant()
            $actualExisting = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant()
            if ($actualExisting -eq $expectedExisting) { return }
        } else {
            return
        }
    }
    if ($NoDownload) {
        throw "Model file missing and -NoDownload was set: $Destination"
    }
    $remotePath = [string]$File.path
    $url = "https://huggingface.co/$Repo/resolve/main/${remotePath}?download=true"
    $tmp = "$Destination.download"
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
    Write-Host "download $Repo / $remotePath"
    if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
        Start-BitsTransfer -Source $url -Destination $tmp
    } else {
        Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
    }
    if ($File.lfs -and $File.lfs.oid) {
        $expected = ([string]$File.lfs.oid).ToLowerInvariant()
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            throw "SHA256 mismatch for $remotePath"
        }
    }
    Move-Item -LiteralPath $tmp -Destination $Destination -Force
}

function Resolve-HfModel([hashtable]$Candidate) {
    $repo = $Candidate.Repo
    $tree = Get-HfTree $repo
    $file = Select-GgufFile $tree $Candidate.QuantPreference
    if (-not $file) { throw "No usable GGUF found for $repo" }
    $leaf = ([string]$file.path) -replace '^.*/',''
    $path = Join-Path (Join-Path $ModelDir (Get-SafeName $repo)) $leaf
    Download-HfFile $file $repo $path
    return @{
        Path = (Resolve-Path -LiteralPath $path).Path
        File = $leaf
        RemotePath = [string]$file.path
    }
}

function Extract-PromptMessages([string]$PromptText) {
    $rx = [regex]'(?s)<\|im_start\|>system\s*(.*?)<\|im_end\|>.*?<\|im_start\|>user\s*(.*?)<\|im_end\|>'
    $match = $rx.Match($PromptText)
    if (-not $match.Success) {
        return @{ System = ""; User = $PromptText }
    }
    return @{
        System = $match.Groups[1].Value.Trim()
        User = $match.Groups[2].Value.Trim()
    }
}

function Convert-ToChatMlPrompt([string]$PromptText) {
    $messages = Extract-PromptMessages $PromptText
    return "<|im_start|>system`n$($messages.System)`n<|im_end|>`n<|im_start|>user`n$($messages.User)`n<|im_end|>`n<|im_start|>assistant`n"
}

function New-PromptProfile([string]$ModelId, [string]$Style) {
    $sourceDir = Join-Path $repoRoot "tools\payload_watermark\prompts"
    $destDir = Join-Path $promptRoot $ModelId
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    foreach ($name in @("default", "self_intro", "group_key")) {
        $src = Join-Path $sourceDir "$name.txt"
        $text = Read-Utf8File $src
        $out = if ($Style -eq "qwen") { $text } else { Convert-ToChatMlPrompt $text }
        Write-Utf8NoBomFile (Join-Path $destDir "$name.txt") $out
    }
    return $destDir
}

function New-TestPayload([int]$Length, [byte]$FirstByte, [int]$Salt) {
    $payload = New-Object byte[] $Length
    for ($idx = 0; $idx -lt $Length; $idx++) {
        $payload[$idx] = [byte](($idx * 53 + 29 + $Salt * 17) -band 0xff)
    }
    if ($Length -gt 0) { $payload[0] = $FirstByte }
    return $payload
}

function Get-UvarintLen([int]$Value) {
    $len = 1
    $v = [uint32]$Value
    while ($v -ge 128) {
        $v = $v -shr 7
        $len++
    }
    return $len
}

function Get-LengthBounds([int]$PayloadLength, [hashtable]$Config) {
    $frameLen = $PayloadLength + (Get-UvarintLen $PayloadLength)
    $digits = $frameLen * 4
    $minFloor = [int]$Config["length_min_chars"]
    $mult = [double]$Config["length_payload_multiplier"]
    $tail = [int]$Config["max_tail_tokens"]
    $upperTail = [int]$Config["length_upper_tail_extra_chars"]
    $upperMult = [double]$Config["length_upper_lower_multiplier"]
    $upperExtra = [int]$Config["length_upper_extra_chars"]
    $lower = [Math]::Max($minFloor, [int][Math]::Ceiling($digits * $mult))
    $upper = [Math]::Max($lower + $tail + $upperTail, [int][Math]::Ceiling($lower * $upperMult) + $upperExtra)
    return @{ Lower = $lower; Upper = $upper }
}

function Get-CjkCount([string]$Text) {
    $count = 0
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int][char]$ch
        if (($code -ge 0x3400 -and $code -le 0x9fff) -or ($code -ge 0xf900 -and $code -le 0xfaff)) {
            $count++
        }
    }
    return $count
}

function Test-WritingOutput([string]$Text, [int]$Lower, [int]$Upper) {
    $issues = [System.Collections.Generic.List[string]]::new()
    $trimmed = ($Text -replace "^\s+", "") -replace "\s+$", ""
    $cjk = Get-CjkCount $trimmed
    if ([string]::IsNullOrWhiteSpace($trimmed)) { $issues.Add("empty") }
    $forbiddenStarts = @(
        (New-TextFromCodePoints @(0x597d,0x7684)),
        (New-TextFromCodePoints @(0x5f53,0x7136)),
        (New-TextFromCodePoints @(0x4ee5,0x4e0b)),
        (New-TextFromCodePoints @(0x8fd9,0x662f)),
        (New-TextFromCodePoints @(0x6b63,0x6587)),
        (New-TextFromCodePoints @(0x6807,0x9898)),
        (New-TextFromCodePoints @(0x8bf7,0x6ce8,0x610f)),
        (New-TextFromCodePoints @(0x62b1,0x6b49)),
        "Sure",
        "Here"
    )
    foreach ($prefix in $forbiddenStarts) {
        if ($trimmed.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $issues.Add("responded_to_task")
            break
        }
    }
    if ($trimmed -match '^[\s\p{P}\p{S}]') { $issues.Add("bad_first_char") }
    if ($trimmed -match '<think|</think|<\|im_|```|[\{\}]') { $issues.Add("template_or_markup") }
    if ($trimmed -match '(?m)^\s*(#{1,6}|[-*]\s+|\d+[\.\)\u3001\uff09])') { $issues.Add("list_or_markdown") }
    if ($trimmed -match '[A-Za-z]{4,}') { $issues.Add("english_or_latin_leak") }
    if ($trimmed.Contains([string][char]0xfffd)) { $issues.Add("mojibake") }
    $savedValidationErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $ErrorActionPreference = $savedValidationErrorAction
    if ($trimmed -match '(\u3002\uff0c|\u3002\s*\uff0c|\uff0c\u3002|,,|\uff0c\uff0c)') { $issues.Add("bad_punctuation") }
    foreach ($needle in @(
        (New-TextFromCodePoints @(0x5199,0x4f5c,0x4efb,0x52a1)),
        (New-TextFromCodePoints @(0x8f93,0x51fa,0x8981,0x6c42)),
        (New-TextFromCodePoints @(0x4e0d,0x8981,0x8f93,0x51fa)),
        (New-TextFromCodePoints @(0x4efb,0x52a1,0x672c,0x8eab))
    )) {
        if ($trimmed.Contains($needle)) {
            $issues.Add("instruction_echo")
            break
        }
    }
    $mojibakeHits = 0
    foreach ($codePoint in @(0x9428, 0x9366, 0x93b4, 0x93c8, 0x9286, 0x95bf, 0x951b, 0x7d1d, 0x6d63, 0x6d93)) {
        $marker = [string][char]$codePoint
        $mojibakeHits += ([regex]::Matches($trimmed, [regex]::Escape($marker))).Count
    }
    if ($mojibakeHits -gt 3) { $issues.Add("mojibake_like_text") }
    if ($cjk -lt $Lower) { $issues.Add("too_short:$cjk<$Lower") }
    if ($cjk -gt $Upper) { $issues.Add("too_long:$cjk>$Upper") }
    return @{
        Valid = ($issues.Count -eq 0)
        Issues = @($issues)
        Cjk = $cjk
        Text = $trimmed
    }
    if ($trimmed -match '(\uFFFD|浣犳|杈撳|銆|锟)') { $issues.Add("mojibake") }
    $ErrorActionPreference = $savedValidationErrorAction
    if ($trimmed -match '(\u3002\uff0c|\u3002\s*\uff0c|\uff0c\u3002|,,|\uff0c\uff0c)') { $issues.Add("bad_punctuation") }
    foreach ($needle in @(
        (New-TextFromCodePoints @(0x5199,0x4f5c,0x4efb,0x52a1)),
        (New-TextFromCodePoints @(0x8f93,0x51fa,0x8981,0x6c42)),
        (New-TextFromCodePoints @(0x4e0d,0x8981,0x8f93,0x51fa)),
        (New-TextFromCodePoints @(0x4efb,0x52a1,0x672c,0x8eab))
    )) {
        if ($trimmed.Contains($needle)) {
            $issues.Add("instruction_echo")
            break
        }
    }
    if ($cjk -lt $Lower) { $issues.Add("too_short:$cjk<$Lower") }
    if ($cjk -gt $Upper) { $issues.Add("too_long:$cjk>$Upper") }
    return @{
        Valid = ($issues.Count -eq 0)
        Issues = @($issues)
        Cjk = $cjk
        Text = $trimmed
    }
}

function Get-HeuristicScore($Validation, [int]$Attempt) {
    $score = 100
    $score -= $Validation.Issues.Count * 18
    $score -= $Attempt * 5
    if ($Validation.Text -match '(.{2,6})\1\1') { $score -= 12 }
    if ($Validation.Text -match '[\uff01\uff1f\u3002]{2,}') { $score -= 6 }
    return [Math]::Max(0, $score)
}

function Quote-Arg([string]$Value) {
    if ($Value -match '[\s"]') {
        return '"' + ($Value -replace '"','\"') + '"'
    }
    return $Value
}

function Start-WorkerSession([string]$ModelPath, [string]$TokenizerId, [string]$PromptDir, [hashtable]$Config) {
    $args = @(
        "--model", $ModelPath,
        "--tokenizer-id", $TokenizerId,
        "--prompt-dir", $PromptDir,
        "--temperature", $Config["temperature"],
        "--top-p", $Config["top_p"],
        "--top-k", $Config["top_k"],
        "--min-k", $Config["min_k"],
        "--ctx", $Config["ctx"],
        "--gpu-layers", $Config["gpu_layers"]
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $WorkerExe
    $psi.Arguments = ($args | ForEach-Object { Quote-Arg $_ }) -join " "
    $psi.WorkingDirectory = Split-Path -Parent $WorkerExe
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $false
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()
    $readyLine = $process.StandardOutput.ReadLine()
    $ready = $readyLine | ConvertFrom-Json
    if (-not $ready.ok) {
        $process.Kill()
        throw "worker ready failed: $readyLine"
    }
    return @{ Process = $process; NextId = 1; Ready = $readyLine }
}

function Invoke-EncodeRequest($Session, [string]$PayloadPath, [string]$TopicPath, [string]$OutPath,
                              [string]$PromptTemplate, [string]$Seed) {
    $id = $Session.NextId
    $Session.NextId = $id + 1
    $request = @{
        id = $id
        cmd = "encode"
        payload = $PayloadPath
        out = $OutPath
        topic_file = $TopicPath
        seed = $Seed
        prompt_template = $PromptTemplate
    } | ConvertTo-Json -Compress
    $Session.Process.StandardInput.WriteLine($request)
    while ($true) {
        $line = $Session.Process.StandardOutput.ReadLine()
        if ($null -eq $line) { throw "worker exited before response id=$id" }
        $message = $line | ConvertFrom-Json
        if ($message.PSObject.Properties["id"] -and [int]$message.id -eq $id) {
            if ($message.PSObject.Properties["type"] -and [string]$message.type -eq "progress") { continue }
            if ($message.ok -eq $true) { return $message }
            throw "worker request failed: $($message.error)"
        }
    }
}

function Stop-WorkerSession($Session) {
    if (-not $Session -or -not $Session.Process -or $Session.Process.HasExited) { return }
    try {
        $id = $Session.NextId
        $Session.NextId = $id + 1
        $Session.Process.StandardInput.WriteLine((@{ id = $id; cmd = "shutdown" } | ConvertTo-Json -Compress))
        $Session.Process.StandardInput.Close()
        [void]$Session.Process.WaitForExit(5000)
    } catch {
    }
    if (-not $Session.Process.HasExited) { $Session.Process.Kill() }
}

$config = Read-WorkerConfig
$promptCases = @(
    @{ Name = "default"; Template = "default"; Topic = (New-TextFromCodePoints @(0x5468,0x672b,0x548c,0x670b,0x53cb,0x4e00,0x8d77,0x53c2,0x52a0,0x6821,0x56ed,0x6d3b,0x52a8)); PayloadLength = 48; FirstByte = 0x21 },
    @{ Name = "self_intro"; Template = "self_intro"; Topic = (New-TextFromCodePoints @(0x6c42,0x804c,0x81ea,0x6211,0x4ecb,0x7ecd)); PayloadLength = 105; FirstByte = 0x21 },
    @{ Name = "group_key"; Template = "group_key"; Topic = (New-TextFromCodePoints @(0x793e,0x56e2,0x62db,0x65b0,0x7b80,0x4ecb,0x3001,0x793e,0x56e2,0x4ecb,0x7ecd)); PayloadLength = 57; FirstByte = 0x51 }
)

$models = @(
    @{ Id = "qwen3_4b"; Label = "Qwen3 4B baseline"; Tokenizer = "qwen3"; PromptStyle = "qwen"; Kind = "baseline"; LocalPatterns = @("Qwen3-4B-Instruct-2507-UD-Q4_K_XL.gguf", "Qwen3-4B-Instruct-2507-Q4_K_M.gguf") },
    @{ Id = "qwen3_1_7b"; Label = "Qwen3 1.7B baseline"; Tokenizer = "qwen3"; PromptStyle = "qwen"; Kind = "baseline_gate"; LocalPatterns = @("Qwen3-1.7B-*.gguf") },
    @{ Id = "minicpm_v_4_6"; Label = "MiniCPM-V 4.6 text-only"; Tokenizer = "minicpmv4_6"; PromptStyle = "chatml"; Kind = "candidate"; Repo = "openbmb/MiniCPM-V-4.6-gguf"; QuantPreference = @("Q4_K_M", "Q4_0", "Q5_K_M", "Q3_K_S") },
    @{ Id = "minicpm4_0_5b_qat"; Label = "MiniCPM4 0.5B QAT Int4"; Tokenizer = "minicpm4"; PromptStyle = "chatml"; Kind = "candidate"; Repo = "openbmb/MiniCPM4-0.5B-QAT-Int4-GGUF"; QuantPreference = @("q4_0", "Q4_0") },
    @{ Id = "bitcpm4_1b"; Label = "BitCPM4 1B"; Tokenizer = "bitcpm4"; PromptStyle = "chatml"; Kind = "candidate"; Repo = "openbmb/BitCPM4-1B-GGUF"; QuantPreference = @("Q4_0", "Q2_K_S") },
    @{ Id = "bitcpm4_0_5b"; Label = "BitCPM4 0.5B"; Tokenizer = "bitcpm4"; PromptStyle = "chatml"; Kind = "candidate"; Repo = "openbmb/BitCPM4-0.5B-GGUF"; QuantPreference = @("Q4_0", "Q2_K_S") },
    @{ Id = "minicpm4_8b_skipped"; Label = "MiniCPM4 8B"; Kind = "skipped"; SkipReason = ">4B, excluded by test plan"; Repo = "openbmb/MiniCPM4-8B-GGUF" },
    @{ Id = "minicpm4_1_8b_skipped"; Label = "MiniCPM4.1 8B"; Kind = "skipped"; SkipReason = ">4B, excluded by test plan"; Repo = "openbmb/MiniCPM4.1-8B-GGUF" }
)
if ($ModelId -and $ModelId.Count -gt 0) {
    $wantedModels = @{}
    foreach ($idValue in $ModelId) {
        foreach ($id in ([string]$idValue -split ',')) {
            $trimmedId = $id.Trim()
            if ($trimmedId.Length -gt 0) { $wantedModels[$trimmedId] = $true }
        }
    }
    $models = @($models | Where-Object { $wantedModels.ContainsKey($_.Id) })
}

$results = [System.Collections.Generic.List[object]]::new()
$skipRows = [System.Collections.Generic.List[object]]::new()

foreach ($model in $models) {
    if ($model.Kind -eq "skipped") {
        $skipRows.Add([PSCustomObject]@{ Model = $model.Label; Repo = $model.Repo; Reason = $model.SkipReason })
        continue
    }
    Write-Host "model $($model.Label)"
    $modelPath = $null
    $modelFile = ""
    try {
        if ($model.Kind -like "baseline*") {
            $modelPath = Resolve-LocalModel $model.LocalPatterns $model.Label
            $modelFile = Split-Path -Leaf $modelPath
        } else {
            $resolved = Resolve-HfModel $model
            $modelPath = $resolved.Path
            $modelFile = $resolved.File
        }
    } catch {
        $results.Add([PSCustomObject]@{
            Model = $model.Label; Kind = $model.Kind; Valid = 0; Total = 0; AvgScore = 0;
            AvgTps = 0; Kept = $false; Reason = "model unavailable: $($_.Exception.Message)"; Samples = @()
        })
        continue
    }

    $promptDir = New-PromptProfile $model.Id $model.PromptStyle
    $modelSamples = [System.Collections.Generic.List[object]]::new()
    $session = $null
    try {
        $session = Start-WorkerSession $modelPath $model.Tokenizer $promptDir $config
        foreach ($case in $promptCases) {
            $bounds = Get-LengthBounds $case.PayloadLength $config
            for ($sampleIdx = 1; $sampleIdx -le $SamplesPerPrompt; $sampleIdx++) {
                $sampleBase = Join-Path $sampleDir "$($model.Id)\$($case.Name)\sample_$sampleIdx"
                New-Item -ItemType Directory -Force -Path $sampleBase | Out-Null
                $best = $null
                for ($attempt = 0; $attempt -le $MaxFixRetries; $attempt++) {
                    $payload = New-TestPayload $case.PayloadLength ([byte]$case.FirstByte) ($sampleIdx * 10 + $attempt)
                    $payloadPath = Join-Path $sampleBase "payload_$attempt.bin"
                    $topicPath = Join-Path $sampleBase "topic.txt"
                    $outPath = Join-Path $sampleBase "output_$attempt.txt"
                    [System.IO.File]::WriteAllBytes($payloadPath, $payload)
                    Write-Utf8NoBomFile $topicPath $case.Topic
                    $seed = "ChineseInputAgent writing eval $($model.Id) $($case.Name) sample=$sampleIdx attempt=$attempt"
                    try {
                        $response = Invoke-EncodeRequest $session $payloadPath $topicPath $outPath $case.Template $seed
                        $text = Read-Utf8File $outPath
                        $validation = Test-WritingOutput $text $bounds.Lower $bounds.Upper
                        $score = Get-HeuristicScore $validation $attempt
                        $tpsValue = 0.0
                        if ($response.PSObject.Properties["tps"]) { $tpsValue = [double]$response.tps }
                        $record = [PSCustomObject]@{
                            Model = $model.Label; ModelId = $model.Id; ModelFile = $modelFile; Prompt = $case.Name;
                            Sample = $sampleIdx; Attempt = $attempt; Valid = $validation.Valid;
                            Issues = ($validation.Issues -join ","); Cjk = $validation.Cjk;
                            Lower = $bounds.Lower; Upper = $bounds.Upper; Score = $score; Tps = $tpsValue;
                            Path = $outPath; Text = $validation.Text
                        }
                        if ($null -eq $best -or $record.Score -gt $best.Score) { $best = $record }
                        if ($validation.Valid) { break }
                    } catch {
                        $record = [PSCustomObject]@{
                            Model = $model.Label; ModelId = $model.Id; ModelFile = $modelFile; Prompt = $case.Name;
                            Sample = $sampleIdx; Attempt = $attempt; Valid = $false;
                            Issues = "worker_error:$($_.Exception.Message)"; Cjk = 0; Lower = $bounds.Lower;
                            Upper = $bounds.Upper; Score = 0; Tps = 0.0; Path = $outPath; Text = ""
                        }
                        if ($null -eq $best) { $best = $record }
                    }
                }
                $modelSamples.Add($best)
                Write-Host ("  {0} sample {1}: valid={2} score={3} issues={4}" -f $case.Name, $sampleIdx, $best.Valid, $best.Score, $best.Issues)
            }
        }
    } catch {
        $results.Add([PSCustomObject]@{
            Model = $model.Label; Kind = $model.Kind; Valid = 0; Total = 0; AvgScore = 0;
            AvgTps = 0; Kept = $false; Reason = "worker failed: $($_.Exception.Message)"; Samples = @()
        })
    } finally {
        Stop-WorkerSession $session
    }

    if ($modelSamples.Count -gt 0) {
        $validCount = @($modelSamples | Where-Object { $_.Valid }).Count
        $avgScore = [Math]::Round((($modelSamples | Measure-Object -Property Score -Average).Average), 2)
        $tpsRows = @($modelSamples | Where-Object { $_.Tps -gt 0 })
        $avgTps = if ($tpsRows.Count -gt 0) { [Math]::Round((($tpsRows | Measure-Object -Property Tps -Average).Average), 2) } else { 0.0 }
        $results.Add([PSCustomObject]@{
            Model = $model.Label; Kind = $model.Kind; Valid = $validCount; Total = $modelSamples.Count;
            AvgScore = $avgScore; AvgTps = $avgTps; Kept = $false; Reason = ""; Samples = @($modelSamples)
        })
    }
}

$gate = $results | Where-Object { $_.Kind -eq "baseline_gate" } | Select-Object -First 1
$gateScore = if ($gate) { [double]$gate.AvgScore } else { 100.0 }
$gateValidRate = if ($gate -and $gate.Total -gt 0) { [double]$gate.Valid / [double]$gate.Total } else { 1.0 }
foreach ($row in $results) {
    if ($row.Kind -eq "candidate") {
        if ($row.Total -gt 0) {
            $rate = [double]$row.Valid / [double]$row.Total
            $row.Kept = ($row.AvgScore -ge $gateScore -and $rate -ge $gateValidRate)
            $row.Reason = if ($row.Kept) { "meets or exceeds Qwen3 1.7B heuristic gate" } else { "below Qwen3 1.7B heuristic gate" }
        }
    } elseif ($row.Kind -eq "baseline_gate") {
        $row.Reason = "retention gate"
    } elseif ($row.Kind -eq "baseline") {
        $row.Reason = "upper reference"
    }
}

$report = [System.Collections.Generic.List[string]]::new()
$report.Add("# OpenBMB writing model evaluation")
$report.Add("")
$report.Add("- Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$report.Add("- Worker: $WorkerExe")
$report.Add("- Prompt source: tools/payload_watermark/prompts/{default,self_intro,group_key}.txt")
$configTemperature = $config["temperature"]
$configTopP = $config["top_p"]
$configTopK = $config["top_k"]
$configMinK = $config["min_k"]
$report.Add("- Sampling: temp=$configTemperature, top_p=$configTopP, top_k=$configTopK, min_k=$configMinK")
$report.Add("- Gate: Qwen3 1.7B avgScore=$gateScore validRate=$([Math]::Round($gateValidRate, 3))")
$report.Add("")
$report.Add("## Summary")
$report.Add("")
$report.Add("| Model | Kind | Valid | Avg score | Avg tps | Retained | Reason |")
$report.Add("| --- | --- | ---: | ---: | ---: | --- | --- |")
foreach ($row in $results) {
    $retainedText = if ($row.Kept) { "yes" } else { "no" }
    $report.Add("| $($row.Model) | $($row.Kind) | $($row.Valid)/$($row.Total) | $($row.AvgScore) | $($row.AvgTps) | $retainedText | $($row.Reason) |")
}
if ($skipRows.Count -gt 0) {
    $report.Add("")
    $report.Add("## Skipped")
    $report.Add("")
    $report.Add("| Model | Repo | Reason |")
    $report.Add("| --- | --- | --- |")
    foreach ($skip in $skipRows) {
        $report.Add("| $($skip.Model) | $($skip.Repo) | $($skip.Reason) |")
    }
}
$report.Add("")
$report.Add("## Samples")
foreach ($row in $results) {
    if (-not $row.Samples -or $row.Samples.Count -eq 0) { continue }
    $report.Add("")
    $report.Add("### $($row.Model)")
    foreach ($sample in $row.Samples) {
        $validText = if ($sample.Valid) { "valid" } else { "invalid" }
        $report.Add("")
        $report.Add("#### $($sample.Prompt) sample $($sample.Sample) attempt $($sample.Attempt) - $validText score=$($sample.Score) cjk=$($sample.Cjk)/$($sample.Lower)-$($sample.Upper)")
        if ($sample.Issues) { $report.Add("- Issues: $($sample.Issues)") }
        $report.Add("")
        $report.Add('```text')
        $report.Add($sample.Text)
        $report.Add('```')
    }
}

$reportPath = Join-Path $OutDir "report.md"
Write-Utf8NoBomFile $reportPath ($report -join "`r`n")
Write-Host "report: $reportPath"

$retained = @($results | Where-Object { $_.Kind -eq "candidate" -and $_.Kept })
if ($retained.Count -eq 0) {
    Write-Host "No OpenBMB candidate met the Qwen3 1.7B gate."
} else {
    Write-Host "Retained candidates:"
    foreach ($row in $retained) { Write-Host "  $($row.Model)" }
}
