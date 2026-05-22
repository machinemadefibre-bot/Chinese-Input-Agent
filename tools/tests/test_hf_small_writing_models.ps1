param(
    [string]$ModelId = "",
    [int]$SamplesPerPrompt = 2,
    [int]$MaxFixRetries = 2,
    [int]$MaxPredict = 360,
    [switch]$SkipDownload
)

$ErrorActionPreference = "Stop"

$processPath = [Environment]::GetEnvironmentVariable("Path", "Process")
if ($processPath) {
    [Environment]::SetEnvironmentVariable("PATH", $null, "Process")
    [Environment]::SetEnvironmentVariable("Path", $processPath, "Process")
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$outRoot = Join-Path $repo "build\tests\hf_small_writing_eval"
$sampleRoot = Join-Path $outRoot "samples"
$modelRoot = Join-Path $outRoot "models"
$promptDir = Join-Path $repo "tools\payload_watermark\prompts"
$llamaCompletion = Join-Path $repo "build\llama_worker_cpu\bin\llama-completion.exe"

if (!(Test-Path $llamaCompletion)) {
    throw "llama-completion.exe not found. Build it with: ninja -C build\llama_worker_cpu llama-completion"
}

New-Item -ItemType Directory -Force -Path $outRoot | Out-Null
New-Item -ItemType Directory -Force -Path $sampleRoot | Out-Null
New-Item -ItemType Directory -Force -Path $modelRoot | Out-Null

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

function Read-Utf8([string]$Path) {
    return [System.IO.File]::ReadAllText($Path, [System.Text.UTF8Encoding]::new($false))
}

function U([string]$Escaped) {
    return [regex]::Replace($Escaped, "\\u([0-9a-fA-F]{4})", {
        param($m)
        return [string][char]([Convert]::ToInt32($m.Groups[1].Value, 16))
    })
}

function Get-CandidateModels {
    $models = @(
        @{
            id = "qwen3_1_7b"
            label = "Qwen3 1.7B baseline"
            local_path = Join-Path $repo "models\Qwen3-1.7B-UD-Q4_K_XL.gguf"
            repo_id = "Qwen/Qwen3-1.7B-GGUF"
            hf_link = "https://hf.co/Qwen/Qwen3-1.7B-GGUF"
            created = "2025-05-05"
            source = "local"
        },
        @{
            id = "qwen3_4b"
            label = "Qwen3 4B reference"
            local_path = Join-Path $repo "models\Qwen3-4B-Instruct-2507-UD-Q4_K_XL.gguf"
            repo_id = "unsloth/Qwen3-4B-Instruct-2507-GGUF"
            hf_link = "https://hf.co/unsloth/Qwen3-4B-Instruct-2507-GGUF"
            created = "2025"
            source = "local"
        },
        @{
            id = "smollm3_3b"
            label = "SmolLM3 3B"
            repo_id = "bartowski/HuggingFaceTB_SmolLM3-3B-GGUF"
            hf_link = "https://hf.co/bartowski/HuggingFaceTB_SmolLM3-3B-GGUF"
            created = "2025-07-08"
            source = "hf"
        },
        @{
            id = "phi4_mini"
            label = "Phi-4 mini instruct"
            repo_id = "MaziyarPanahi/Phi-4-mini-instruct-GGUF"
            hf_link = "https://hf.co/MaziyarPanahi/Phi-4-mini-instruct-GGUF"
            created = "2025-03-01"
            source = "hf"
        },
        @{
            id = "lfm2_5_1_2b"
            label = "LFM2.5 1.2B Instruct"
            repo_id = "LiquidAI/LFM2.5-1.2B-Instruct-GGUF"
            hf_link = "https://hf.co/LiquidAI/LFM2.5-1.2B-Instruct-GGUF"
            created = "2026-01-04"
            source = "hf"
        },
        @{
            id = "granite_3_3_2b"
            label = "Granite 3.3 2B Instruct"
            repo_id = "bartowski/ibm-granite_granite-3.3-2b-instruct-GGUF"
            hf_link = "https://hf.co/bartowski/ibm-granite_granite-3.3-2b-instruct-GGUF"
            created = "2025-04-17"
            source = "hf"
        },
        @{
            id = "gemma3_4b"
            label = "Gemma 3 4B IT"
            repo_id = "MaziyarPanahi/gemma-3-4b-it-GGUF"
            hf_link = "https://hf.co/MaziyarPanahi/gemma-3-4b-it-GGUF"
            created = "2025-03-12"
            source = "hf"
        },
        @{
            id = "deepseek_r1_qwen_1_5b"
            label = "DeepSeek R1 Distill Qwen 1.5B"
            repo_id = "unsloth/DeepSeek-R1-Distill-Qwen-1.5B-GGUF"
            hf_link = "https://hf.co/unsloth/DeepSeek-R1-Distill-Qwen-1.5B-GGUF"
            created = "2025-01-20"
            source = "hf"
        }
    )

    if ([string]::IsNullOrWhiteSpace($ModelId)) {
        return $models
    }

    $ids = $ModelId.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    return $models | Where-Object { $ids -contains $_.id }
}

function Get-HfTree([string]$RepoId) {
    $uri = "https://huggingface.co/api/models/$RepoId/tree/main?recursive=1&expand=1"
    return Invoke-RestMethod -Uri $uri -Headers @{ "User-Agent" = "ChineseInputAgent-writing-eval" }
}

function Select-GgufFile($Tree) {
    $files = @($Tree | Where-Object {
        $_.type -eq "file" -and
        $_.path -match "\.gguf$" -and
        $_.path -notmatch "(?i)mmproj|projector|vision|visual|encoder|tokenizer|imatrix"
    })

    if ($files.Count -eq 0) {
        throw "No usable GGUF files found"
    }

    $quantPreference = @(
        "UD-Q4_K_XL",
        "Q4_K_M",
        "Q4_K_S",
        "Q4_0",
        "IQ4_XS",
        "Q3_K_M",
        "Q3_K_S",
        "Q5_K_M"
    )

    foreach ($quant in $quantPreference) {
        $match = @($files | Where-Object { $_.path -match [regex]::Escape($quant) } | Sort-Object size | Select-Object -First 1)
        if ($match.Count -gt 0) {
            return $match[0]
        }
    }

    return ($files | Sort-Object size | Select-Object -First 1)
}

function Download-HfFile([string]$RepoId, [string]$Path, [string]$Destination) {
    if (Test-Path $Destination) {
        return
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
    $escapedPath = ([uri]::EscapeDataString($Path)).Replace("%2F", "/")
    $uri = "https://huggingface.co/$RepoId/resolve/main/$escapedPath"
    $partial = "$Destination.partial"
    if (Test-Path $partial) {
        Remove-Item -LiteralPath $partial -Force
    }

    Write-Host "Downloading $RepoId/$Path"
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source -L --fail --retry 3 --retry-delay 2 -o $partial $uri
        if ($LASTEXITCODE -ne 0) {
            throw "curl failed with exit code $LASTEXITCODE"
        }
    } else {
        try {
            Start-BitsTransfer -Source $uri -Destination $partial -ErrorAction Stop
        } catch {
            Invoke-WebRequest -Uri $uri -OutFile $partial -Headers @{ "User-Agent" = "ChineseInputAgent-writing-eval" }
        }
    }
    Move-Item -LiteralPath $partial -Destination $Destination -Force
}

function Resolve-ModelPath([hashtable]$Model) {
    if ($Model.source -eq "local") {
        if (!(Test-Path $Model.local_path)) {
            throw "Missing local model: $($Model.local_path)"
        }
        $Model.path = $Model.local_path
        $Model.file = Split-Path -Leaf $Model.local_path
        return $Model
    }

    $repoDir = Join-Path $modelRoot ($Model.repo_id.Replace("/", "_"))
    $existing = @(Get-ChildItem -Path $repoDir -Filter *.gguf -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch "(?i)mmproj|projector|vision|visual|encoder|tokenizer|imatrix" } |
        Sort-Object Length)
    if ($existing.Count -gt 0) {
        $Model.path = $existing[0].FullName
        $Model.file = $existing[0].Name
        return $Model
    }

    if ($SkipDownload) {
        throw "Model not downloaded and -SkipDownload was set: $($Model.repo_id)"
    }

    $tree = Get-HfTree $Model.repo_id
    $file = Select-GgufFile $tree
    $dest = Join-Path $repoDir ($file.path -replace "[\\/]", "_")
    Download-HfFile $Model.repo_id $file.path $dest
    $Model.path = $dest
    $Model.file = $file.path
    return $Model
}

function Convert-TemplateToMessages([string]$TemplateName, [string]$Topic, [string]$LengthRequirement) {
    $templatePath = Join-Path $promptDir "$TemplateName.txt"
    $template = Read-Utf8 $templatePath
    $template = $template.Replace("{topic}", $Topic)
    $template = $template.Replace("{length_requirement}", $LengthRequirement)
    $template = $template.Replace("{prompt_template}", $Topic)
    $template = $template.Replace("{outline}", "")
    $template = $template.Replace("{fingerprint}", "ABCDEFGH")

    $systemMatch = [regex]::Match($template, "(?s)<\|im_start\|>system\s*(.*?)<\|im_end\|>")
    $userMatch = [regex]::Match($template, "(?s)<\|im_start\|>user\s*(.*?)<\|im_end\|>")
    if (!$systemMatch.Success -or !$userMatch.Success) {
        throw "Prompt template $TemplateName does not look like a ChatML prompt"
    }

    return @{ system = $systemMatch.Groups[1].Value.Trim(); user = $userMatch.Groups[1].Value.Trim() }
}

function Count-Cjk([string]$Text) {
    $count = 0
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int][char]$ch
        if (($code -ge 0x4e00 -and $code -le 0x9fff) -or
            ($code -ge 0x3400 -and $code -le 0x4dbf) -or
            ($code -ge 0xf900 -and $code -le 0xfaff)) {
            $count++
        }
    }
    return $count
}

function Normalize-GeneratedText([string]$Raw) {
    $text = $Raw
    $logPos = $text.IndexOf("`nmain: ")
    if ($logPos -ge 0) {
        $text = $text.Substring(0, $logPos)
    }
    $text = $text -replace "\[end of text\]", ""
    $text = $text -replace "(?s)<think>.*?</think>", ""
    $text = $text -replace "<\|im_end\|>", ""
    return $text.Trim()
}

function Test-WritingOutput([string]$Text, [int]$MinChars, [int]$MaxChars) {
    $issues = New-Object System.Collections.Generic.List[string]
    $cjk = Count-Cjk $Text
    if ($cjk -lt $MinChars) { $issues.Add("too_short:$cjk") }
    if ($cjk -gt $MaxChars) { $issues.Add("too_long:$cjk") }
    if ($Text -match "<think>|</think>|<\|im_|Markdown|JSON") { $issues.Add("template_or_meta_leak") }

    $taskPrefixPattern = U "^(\u6807\u9898|\u6b63\u6587|\u6587\u7ae0|\u81ea\u6211\u4ecb\u7ecd|\u793e\u56e2\u4ecb\u7ecd|\u4ee5\u4e0b\u662f|\u597d\u7684|\u5f53\u7136|\u62b1\u6b49|\u4efb\u52a1|\u8f93\u51fa)"
    if ($Text -match $taskPrefixPattern) { $issues.Add("task_reply_prefix") }

    $numberedPattern = U "^\s*[\*\-\d\u4e00\u4e8c\u4e09\u56db\u4e94\u516d\u4e03\u516b\u4e5d\u5341]+[\.\u3001\)]"
    if ($Text -match $numberedPattern) { $issues.Add("list_or_numbered_output") }

    if ($Text -match "[A-Za-z]{12,}") { $issues.Add("long_english_fragment") }

    $badPunctuationPattern = U "\u3002\uff0c|\uff0c\u3002|\uff1b\uff0c|\uff0c\uff1b|\u3002\u3002|\uff0c\uff0c"
    if ($Text -match $badPunctuationPattern) { $issues.Add("bad_punctuation") }

    if ($Text -match (U "\ufffd")) { $issues.Add("mojibake") }
    if ([string]::IsNullOrWhiteSpace($Text)) { $issues.Add("empty") }
    return @{ ok = ($issues.Count -eq 0); issues = @($issues); cjk = $cjk }
}

function Quote-ProcessArg([string]$Arg) {
    if ($Arg -notmatch '[\s"]') {
        return $Arg
    }
    return '"' + ($Arg.Replace('\', '\\').Replace('"', '\"')) + '"'
}

function Invoke-ProcessCapture([string]$ExePath, [string[]]$ArgList, [string]$StdoutPath, [string]$StderrPath) {
    $quotedArgs = (($ArgList | ForEach-Object { Quote-ProcessArg $_ }) -join " ")
    $process = Start-Process -FilePath $ExePath -ArgumentList $quotedArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath
    return $process.ExitCode
}

function Invoke-FreeWrite([hashtable]$Model, [hashtable]$Case, [int]$Attempt, [string]$CaseDir) {
    $outPath = Join-Path $CaseDir "raw_$Attempt.txt"
    $logPath = Join-Path $CaseDir "llama_$Attempt.log"
    $stdoutPath = Join-Path $CaseDir "stdout_$Attempt.txt"
    $stderrPath = Join-Path $CaseDir "stderr_$Attempt.txt"
    $sysPath = Join-Path $CaseDir "system_$Attempt.txt"
    $userPath = Join-Path $CaseDir "user_$Attempt.txt"
    Write-Utf8NoBom $sysPath $Case.messages.system
    Write-Utf8NoBom $userPath $Case.messages.user

    $processArgs = @(
        "-m", $Model.path,
        "-sysf", $sysPath,
        "-f", $userPath,
        "--conversation",
        "--single-turn",
        "--jinja",
        "--reasoning", "off",
        "--reasoning-budget", "0",
        "--temp", "0.68",
        "--top-p", "0.80",
        "-c", "4096",
        "-n", "$MaxPredict",
        "--no-perf",
        "--no-display-prompt",
        "--log-file", $logPath
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $exitCode = Invoke-ProcessCapture -ExePath $llamaCompletion -ArgList $processArgs -StdoutPath $stdoutPath -StderrPath $stderrPath
    $sw.Stop()
    $raw = if (Test-Path $stdoutPath) { Read-Utf8 $stdoutPath } else { "" }
    Write-Utf8NoBom $outPath $raw
    if ($exitCode -ne 0) {
        $stderr = if (Test-Path $stderrPath) { (Read-Utf8 $stderrPath).Trim() } else { "" }
        if ($stderr.Length -gt 180) { $stderr = $stderr.Substring(0, 180) }
        return @{ ok = $false; text = ""; raw = $raw; seconds = $sw.Elapsed.TotalSeconds; issues = @("exit_code:$exitCode $stderr"); cjk = 0 }
    }

    $text = Normalize-GeneratedText $raw
    $check = Test-WritingOutput $text $Case.minChars $Case.maxChars
    Write-Utf8NoBom (Join-Path $CaseDir "clean_$Attempt.txt") $text
    return @{ ok = $check.ok; text = $text; raw = $raw; seconds = $sw.Elapsed.TotalSeconds; issues = $check.issues; cjk = $check.cjk }
}

$cases = @(
    @{
        id = "default"
        template = "default"
        topic = U "\u6821\u56ed\u6d3b\u52a8\u540e\u7684\u4e2a\u4eba\u611f\u53d7"
        minChars = 120
        maxChars = 220
        length = U "\u5199 120 \u5230 220 \u4e2a\u6c49\u5b57\u3002"
    },
    @{
        id = "self_intro"
        template = "self_intro"
        topic = U "\u6c42\u804c\u7528\u81ea\u6211\u4ecb\u7ecd"
        minChars = 120
        maxChars = 220
        length = U "\u5199 120 \u5230 220 \u4e2a\u6c49\u5b57\u3002"
    },
    @{
        id = "group_key"
        template = "group_key"
        topic = U "\u793e\u56e2\u62db\u65b0\u7b80\u4ecb\u3001\u793e\u56e2\u4ecb\u7ecd"
        minChars = 120
        maxChars = 220
        length = U "\u5199 120 \u5230 220 \u4e2a\u6c49\u5b57\u3002"
    }
)

foreach ($case in $cases) {
    $case.messages = Convert-TemplateToMessages $case.template $case.topic $case.length
}

$reportRows = New-Object System.Collections.Generic.List[object]
$models = Get-CandidateModels
if (!$models -or $models.Count -eq 0) {
    throw "No models selected"
}

foreach ($model in $models) {
    try {
        $model = Resolve-ModelPath $model
    } catch {
        $reportRows.Add([pscustomobject]@{
            model = $model.id
            label = $model.label
            link = $model.hf_link
            created = $model.created
            file = ""
            keep = "no"
            valid = 0
            total = 0
            avg_seconds = ""
            notes = $_.Exception.Message
        })
        continue
    }

    $valid = 0
    $total = 0
    $seconds = New-Object System.Collections.Generic.List[double]
    $allIssues = New-Object System.Collections.Generic.List[string]
    $modelDir = Join-Path $sampleRoot $model.id
    if (Test-Path $modelDir) {
        Remove-Item -LiteralPath $modelDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $modelDir | Out-Null

    foreach ($case in $cases) {
        for ($sample = 1; $sample -le $SamplesPerPrompt; $sample++) {
            $total++
            $caseDir = Join-Path $modelDir "$($case.id)_$sample"
            New-Item -ItemType Directory -Force -Path $caseDir | Out-Null
            $accepted = $false

            for ($attempt = 1; $attempt -le (1 + $MaxFixRetries); $attempt++) {
                Write-Host "[$($model.id)] $($case.id) sample $sample attempt $attempt"
                $result = Invoke-FreeWrite $model $case $attempt $caseDir
                $seconds.Add([double]$result.seconds)
                if ($result.ok) {
                    $valid++
                    $accepted = $true
                    break
                }
                foreach ($issue in $result.issues) {
                    $allIssues.Add("$($case.id):$issue")
                }
            }

            if (!$accepted) {
                Write-Utf8NoBom (Join-Path $caseDir "rejected.txt") "Rejected after $MaxFixRetries retry/revision attempts."
            }
        }
    }

    $avg = if ($seconds.Count -gt 0) { [Math]::Round(($seconds | Measure-Object -Average).Average, 2) } else { "" }
    $notes = if ($allIssues.Count -gt 0) {
        (($allIssues | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join "; ")
    } else {
        "all samples passed automatic checks"
    }

    $reportRows.Add([pscustomobject]@{
        model = $model.id
        label = $model.label
        link = $model.hf_link
        created = $model.created
        file = $model.file
        keep = if ($valid -eq $total) { "candidate" } else { "no" }
        valid = $valid
        total = $total
        avg_seconds = $avg
        notes = $notes
    })
}

$baseline = $reportRows | Where-Object { $_.model -eq "qwen3_1_7b" } | Select-Object -First 1
$baselineRate = if ($baseline -and $baseline.total -gt 0) { [double]$baseline.valid / [double]$baseline.total } else { 1.0 }
foreach ($row in $reportRows) {
    if ($row.model -notmatch "^qwen3_" -and $row.total -gt 0) {
        $rate = [double]$row.valid / [double]$row.total
        if ($rate -ge $baselineRate -and $row.keep -eq "candidate") {
            $row.keep = "retain"
        } elseif ($row.keep -eq "candidate") {
            $row.keep = "below-baseline"
        }
    }
}

$report = New-Object System.Collections.Generic.List[string]
$report.Add("# Hugging Face small writing evaluation")
$report.Add("")
$report.Add("Scope: 2025+ GGUF language models at 4B parameters or below, tested through llama.cpp with each model's GGUF chat template.")
$report.Add("Mode: free writing only. This does not test carrier encode/decode reliability and does not change app defaults.")
$report.Add("")
$report.Add("| model | label | created | file | keep? | valid/total | avg seconds | notes |")
$report.Add("|---|---|---:|---|---:|---:|---:|---|")
foreach ($row in $reportRows) {
    $notes = [string]$row.notes
    $notes = $notes.Replace("|", "\|")
    $file = ([string]$row.file).Replace("|", "\|")
    $label = "[$($row.label)]($($row.link))"
    $report.Add("| $($row.model) | $label | $($row.created) | $file | $($row.keep) | $($row.valid)/$($row.total) | $($row.avg_seconds) | $notes |")
}
$report.Add("")
$report.Add("Samples are under samples/. Downloaded models are test artifacts under models/.")

Write-Utf8NoBom (Join-Path $outRoot "report.md") ($report -join "`n")
Write-Host "Report written to $outRoot\report.md"
