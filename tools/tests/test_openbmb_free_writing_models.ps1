param(
    [string]$ModelId = "",
    [int]$SamplesPerPrompt = 3,
    [int]$MaxFixRetries = 3,
    [int]$MaxPredict = 420
)

$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$outRoot = Join-Path $repo "build\tests\openbmb_free_writing_eval"
$sampleRoot = Join-Path $outRoot "samples"
$modelRoot = Join-Path $repo "build\tests\openbmb_writing_eval\models"
$promptDir = Join-Path $repo "tools\payload_watermark\prompts"
$llamaCompletion = Join-Path $repo "build\llama_worker_cpu\bin\llama-completion.exe"

if (!(Test-Path $llamaCompletion)) {
    throw "llama-completion.exe not found. Build it with: ninja -C build\llama_worker_cpu llama-completion"
}

New-Item -ItemType Directory -Force -Path $outRoot | Out-Null
New-Item -ItemType Directory -Force -Path $sampleRoot | Out-Null

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

function Get-ModelList {
    $models = @(
        @{
            id = "qwen3_1_7b"
            label = "Qwen3 1.7B baseline"
            path = Join-Path $repo "models\Qwen3-1.7B-UD-Q4_K_XL.gguf"
            source = "local"
        },
        @{
            id = "qwen3_4b"
            label = "Qwen3 4B reference"
            path = Join-Path $repo "models\Qwen3-4B-Instruct-2507-UD-Q4_K_XL.gguf"
            source = "local"
        },
        @{
            id = "minicpm_v_4_6"
            label = "MiniCPM-V 4.6 Q4_K_M"
            path = Join-Path $modelRoot "openbmb_MiniCPM-V-4.6-gguf\MiniCPM-V-4_6-Q4_K_M.gguf"
            source = "openbmb/MiniCPM-V-4.6-gguf"
        },
        @{
            id = "minicpm4_0_5b_qat"
            label = "MiniCPM4 0.5B QAT Int4"
            path = Join-Path $modelRoot "openbmb_MiniCPM4-0.5B-QAT-Int4-GGUF\MiniCPM4-0.5B-QAT-Int4_gptq_aware_q4_0.gguf"
            source = "openbmb/MiniCPM4-0.5B-QAT-Int4-GGUF"
        },
        @{
            id = "bitcpm4_1b"
            label = "BitCPM4 1B q4_0"
            path = Join-Path $modelRoot "openbmb_BitCPM4-1B-GGUF\BitCPM4-1B-q4_0.gguf"
            source = "openbmb/BitCPM4-1B-GGUF"
        },
        @{
            id = "bitcpm4_0_5b"
            label = "BitCPM4 0.5B q4_0"
            path = Join-Path $modelRoot "openbmb_BitCPM4-0.5B-GGUF\BitCPM4-0.5B-q4_0.gguf"
            source = "openbmb/BitCPM4-0.5B-GGUF"
        }
    )

    if ([string]::IsNullOrWhiteSpace($ModelId)) {
        return $models
    }

    $wanted = $ModelId.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    return $models | Where-Object { $wanted -contains $_.id }
}

function Convert-TemplateToMessages([string]$TemplateName, [string]$Topic, [string]$LengthRequirement) {
    $template = Read-Utf8 (Join-Path $promptDir "$TemplateName.txt")
    $text = $template.Replace("{topic}", $Topic).
        Replace("{length_requirement}", $LengthRequirement).
        Replace("{min_chars}", "120").
        Replace("{max_chars}", "220")

    $system = ""
    $user = ""
    if ($text -match "(?s)<\|im_start\|>system\s*(.*?)<\|im_end\|>") {
        $system = $Matches[1].Trim()
    }
    if ($text -match "(?s)<\|im_start\|>user\s*(.*?)<\|im_end\|>") {
        $user = $Matches[1].Trim()
    }
    if ([string]::IsNullOrWhiteSpace($system) -or [string]::IsNullOrWhiteSpace($user)) {
        throw "Prompt template $TemplateName does not look like a ChatML prompt"
    }

    return @{ system = $system; user = $user }
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

function Invoke-FreeWrite([hashtable]$Model, [hashtable]$Case, [int]$Attempt, [string]$CaseDir) {
    $sysPath = Join-Path $CaseDir "system_$Attempt.txt"
    $userPath = Join-Path $CaseDir "user_$Attempt.txt"
    $outPath = Join-Path $CaseDir "raw_$Attempt.txt"
    $logPath = Join-Path $CaseDir "llama_$Attempt.log"
    $stdoutPath = Join-Path $CaseDir "stdout_$Attempt.txt"
    $stderrPath = Join-Path $CaseDir "stderr_$Attempt.txt"
    Write-Utf8NoBom $sysPath $Case.messages.system
    Write-Utf8NoBom $userPath $Case.messages.user

    $args = @(
        "-m", $Model.path,
        "-sysf", $sysPath,
        "-f", $userPath,
        "--conversation",
        "--single-turn",
        "--jinja",
        "--reasoning", "off",
        "--temp", "0.68",
        "--top-p", "0.80",
        "-n", "$MaxPredict",
        "--no-perf",
        "--no-display-prompt",
        "--log-file", $logPath
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $llamaCompletion -ArgumentList $args -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $exitCode = $process.ExitCode
    $sw.Stop()
    $raw = if (Test-Path $stdoutPath) { Read-Utf8 $stdoutPath } else { "" }
    Write-Utf8NoBom $outPath $raw
    if ($exitCode -ne 0) {
        return @{ ok = $false; text = ""; raw = $raw; seconds = $sw.Elapsed.TotalSeconds; issues = @("exit_code:$exitCode"); cjk = 0 }
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
$models = Get-ModelList
if (!$models -or $models.Count -eq 0) {
    throw "No models selected"
}

foreach ($model in $models) {
    if (!(Test-Path $model.path)) {
        $reportRows.Add([pscustomobject]@{
            model = $model.id
            label = $model.label
            kept = "no"
            valid = 0
            total = 0
            avg_seconds = ""
            notes = "missing model: $($model.path)"
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
    $kept = if ($valid -eq $total) { "candidate" } else { "no" }
    $notes = if ($allIssues.Count -gt 0) {
        (($allIssues | Group-Object | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join "; ")
    } else {
        "all samples passed automatic checks"
    }
    $reportRows.Add([pscustomobject]@{
        model = $model.id
        label = $model.label
        kept = $kept
        valid = $valid
        total = $total
        avg_seconds = $avg
        notes = $notes
    })
}

$report = New-Object System.Collections.Generic.List[string]
$report.Add("# OpenBMB free writing evaluation")
$report.Add("")
$report.Add("Mode: unrestricted writing generation through llama.cpp chat/completion, not carrier/top-k encode.")
$report.Add("Criteria: fluency, rule following, and rough length control. Automatic checks are a first pass; manual sample review is still required for final taste decisions.")
$report.Add("")
$report.Add("| model | label | keep? | valid/total | avg seconds | notes |")
$report.Add("|---|---|---:|---:|---:|---|")
foreach ($row in $reportRows) {
    $notes = [string]$row.notes
    $notes = $notes.Replace("|", "\|")
    $report.Add("| $($row.model) | $($row.label) | $($row.kept) | $($row.valid)/$($row.total) | $($row.avg_seconds) | $notes |")
}
$report.Add("")
$report.Add("Samples are under samples/. Models are local test artifacts and are not app defaults.")

Write-Utf8NoBom (Join-Path $outRoot "report.md") ($report -join "`n")
Write-Host "Report written to $outRoot\report.md"
