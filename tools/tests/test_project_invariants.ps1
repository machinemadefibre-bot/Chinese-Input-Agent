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

function Get-RepoSlice {
    param(
        [string]$Text,
        [string]$Start,
        [string]$End
    )
    $startIndex = $Text.IndexOf($Start)
    Assert-True ($startIndex -ge 0) "start marker not found: $Start"
    $endIndex = $Text.IndexOf($End, $startIndex + $Start.Length)
    Assert-True ($endIndex -gt $startIndex) "end marker not found after: $Start"
    return $Text.Substring($startIndex, $endIndex - $startIndex)
}

function Test-InstallerDownloadsWorkerDefaultModel {
    $packageBat = Read-RepoFile "package-mingw.bat"
    $installer = Read-RepoFile "src\installer.c"
    $installerConfig = Read-RepoFile "src\app_installer_config.h"
    $appPaths = Read-RepoFile "src\app_paths.h"
    $workerCpp = Read-RepoFile "tools\payload_watermark\cia_llama_worker.cpp"

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
    Assert-True ($workerNames -contains "base_model.gguf") "worker should search for installer-downloaded base_model.gguf"
    Assert-True $installerConfig.Contains("APP_INSTALL_MODEL_DOWNLOAD_URL") "installer should define a model download URL"
    Assert-True $installerConfig.Contains("APP_INSTALL_MODEL_DOWNLOAD_SHA256") "installer should verify the downloaded model"
    Assert-True $appPaths.Contains("APP_INSTALL_MODEL_NAME L`"base_model.gguf`"") "installer should write the worker default model name"
    Assert-True $installer.Contains("APP_INSTALL_MODEL_NAME") "installer should use the centralized worker default model name"
    Assert-True (-not $packageBat.Contains("copy /y `"%MODEL_SRC%`"")) "portable package should not embed the GGUF model"
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

function Test-CryptoBoxUsesOpaqueContext {
    $header = Read-RepoFile "src\crypto_box.h"
    $impl = Read-RepoFile "src\crypto_box.c"

    Assert-True $header.Contains("typedef struct CRYPTO_BOX CRYPTO_BOX;") "crypto_box.h should expose CRYPTO_BOX as an opaque context"
    Assert-True $header.Contains("crypto_box_open(") "crypto_box.h should expose crypto_box_open"
    Assert-True $header.Contains("crypto_box_close(") "crypto_box.h should expose crypto_box_close"
    Assert-True $header.Contains("crypto_box_encrypt(CRYPTO_BOX *box") "crypto_box_encrypt should take an explicit context"
    Assert-True $header.Contains("crypto_box_decrypt(CRYPTO_BOX *box") "crypto_box_decrypt should take an explicit context"
    Assert-True (-not $header.Contains("crypto_box_init(")) "crypto_box_init should not remain in the public API"
    Assert-True (-not $header.Contains("crypto_box_shutdown(")) "crypto_box_shutdown should not remain in the public API"
    Assert-True $impl.Contains("struct CRYPTO_BOX") "crypto_box.c should own the CRYPTO_BOX layout"
    Assert-True (-not $impl.Contains("static BYTE g_master_key")) "crypto_box.c should not keep a global master key"
    Assert-True (-not $impl.Contains("static WCHAR g_state_path")) "crypto_box.c should not keep a global state path"
}

function Test-CryptoBoxUsesSessionTransport {
    $header = Read-RepoFile "src\crypto_box.h"
    $impl = Read-RepoFile "src\crypto_box.c"
    $groups = Read-RepoFile "src\app_groups.c"

    Assert-True $impl.Contains("#define STATE_VERSION 5u") "crypto session state should use the session-capable state version"
    Assert-True $impl.Contains("#define MESSAGE_TAG_BYTES 12") "message AES-GCM tag should be 12 bytes"
    Assert-True $impl.Contains("#define CONTACT_FINGERPRINT_CHARS 8") "contact fingerprint should be 8 base32 characters"
    Assert-True $impl.Contains('L"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"') "contact fingerprint should use the ambiguity-reduced base32 alphabet"
    Assert-True $groups.Contains("#define GROUP_FINGERPRINT_CHARS 8") "group package fingerprint should be 8 base32 characters"
    Assert-True $groups.Contains('L"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"') "group fingerprint should use the ambiguity-reduced base32 alphabet"
    Assert-True $impl.Contains("#define SESSION_HEADER_BYTES (1 + SESSION_ID_BYTES + SESSION_COUNTER_BYTES)") "session messages should use the compact header"
    Assert-True $impl.Contains("SESSION_MAX_SKIPPED_KEYS") "session transport should keep a bounded skipped-key cache"
    Assert-True $impl.Contains("derive_handshake_session") "contact package exchange should derive session chains"
    Assert-True $impl.Contains("derive_chain_step") "session messages should ratchet the symmetric chain"
    Assert-True (-not $impl.Contains("derive_message_key(")) "legacy per-message ECIES key derivation should not remain"
    Assert-True $header.Contains("crypto_box_contact_package_recipient_public") "app_flow should be able to route addressed session key packages"
}

function Test-ProfilesDoNotManageCryptoLifecycle {
    $header = Read-RepoFile "src\app_profiles.h"
    $profiles = Read-RepoFile "src\app_profiles.c"
    $activate = Get-RepoSlice $profiles "BOOL profiles_activate" "int profiles_count"

    Assert-True $profiles.Contains("profiles_open_crypto(") "app_profiles.c should expose profiles_open_crypto"
    Assert-True $header.Contains("profiles_lock_inactive_masters(") "app_profiles.h should expose inactive master-key locking"
    Assert-True $header.Contains("typedef struct KEY_PROFILE KEY_PROFILE;") "app_profiles.h should keep KEY_PROFILE opaque"
    Assert-True (-not $header.Contains("BYTE master_key[")) "app_profiles.h should not expose profile master-key fields"
    Assert-True (-not $header.Contains("master_loaded")) "app_profiles.h should not expose profile master-key residency state"
    Assert-True $header.Contains("profiles_with_master_key(") "app_profiles.h should expose explicit master-key lease API"
    Assert-True $profiles.Contains("SecureZeroMemory(g_profiles[profile_idx].master_key") "inactive profile master keys should be securely cleared"
    Assert-True (-not $activate.Contains("crypto_box_init")) "profiles_activate should not initialize crypto_box"
    Assert-True (-not $activate.Contains("crypto_box_shutdown")) "profiles_activate should not shut down crypto_box"
    Assert-True (-not $activate.Contains("crypto_box_export_contact_package")) "profiles_activate should not export crypto material"
    Assert-True (-not $profiles.Contains("profiles_build_key_package")) "profile layer should not build key packages"
}

function Test-KeyPersistenceUsesAtomicWrites {
    $shared = Read-RepoFile "src\app_shared.c"
    $profiles = Read-RepoFile "src\app_profiles.c"
    $archive = Read-RepoFile "src\app_archive.c"
    $crypto = Read-RepoFile "src\crypto_box.c"

    Assert-True $shared.Contains("write_file_bytes_atomic") "app_shared.c should implement write_file_bytes_atomic"
    Assert-True $shared.Contains("MoveFileExW") "atomic writes should replace via MoveFileExW"
    Assert-True $shared.Contains("MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH") "atomic writes should use replace and write-through"
    Assert-True (Get-RepoSlice $profiles "BOOL profiles_save" "BOOL profiles_create_from_master").Contains("write_file_bytes_atomic") "profiles_save should use atomic writes"
    Assert-True (Get-RepoSlice $archive "static BOOL archive_append_with_master" "BOOL archive_load_text").Contains("write_file_bytes_atomic") "archive rewrite should use atomic writes"
    Assert-True (Get-RepoSlice $crypto "static BOOL write_file_all" "static BOOL box_file_exists").Contains("write_file_bytes_atomic") "crypto state save should use atomic writes"
}

function Test-AppFlowOwnsCryptoBusinessFlow {
    $main = Read-RepoFile "src\main.c"
    $work = Read-RepoFile "src\app_work.c"
    $flow = Read-RepoFile "src\app_flow.c"
    $messageFlow = Read-RepoFile "src\app_message_flow.c"
    $contactFlow = Read-RepoFile "src\app_contact_flow.c"
    $carrierFlow = Read-RepoFile "src\app_carrier_flow.c"
    $header = Read-RepoFile "src\app_flow.h"

    foreach ($call in @(
        "crypto_box_encrypt(",
        "crypto_box_decrypt(",
        "crypto_box_import_contact_package(",
        "crypto_box_export_contact_package(",
        "crypto_box_get_public_key(",
        "crypto_box_get_remote_public_key(",
        "crypto_box_get_public_fingerprint(",
        "crypto_box_contact_package_fingerprint(",
        "local_topk_encode_payload(",
        "local_topk_decode_payload("
    )) {
        Assert-True (-not $main.Contains($call)) "main.c should not directly call business flow API: $call"
    }
    Assert-True $main.Contains("app_work_start(") "main.c should dispatch background work through app_work"
    Assert-True $main.Contains("CRYPTO_BOX *g_active_box") "main.c should hold the active crypto context"
    Assert-True $work.Contains("app_flow_encrypt_message(") "app_work.c should dispatch encryption through app_flow"
    Assert-True ($work.Contains("app_flow_decrypt_clip_auto(") -or $work.Contains("app_flow_decrypt_clip_auto_profile(")) "app_work.c should dispatch decryption through app_flow"
    Assert-True $flow.Contains("app_message_flow_encrypt_message(") "app_flow.c should remain a thin message-flow facade"
    Assert-True $flow.Contains("app_contact_flow_import_key(") "app_flow.c should remain a thin contact-flow facade"
    Assert-True $flow.Contains("app_carrier_extract_exchange_body(") "app_flow.c should remain a thin carrier-flow facade"
    Assert-True $messageFlow.Contains("crypto_box_encrypt(") "app_message_flow.c should own message encryption orchestration"
    Assert-True $messageFlow.Contains("app_groups_decrypt_message(") "app_message_flow.c should own group/private decrypt routing"
    Assert-True $contactFlow.Contains("crypto_box_import_contact_package(") "app_contact_flow.c should own contact key import orchestration"
    Assert-True $contactFlow.Contains("crypto_box_export_contact_package(") "app_contact_flow.c should own contact key export orchestration"
    Assert-True $carrierFlow.Contains("local_topk_encode_payload(") "app_carrier_flow.c should own top-k encode calls"
    Assert-True $carrierFlow.Contains("local_topk_decode_payload(") "app_carrier_flow.c should own top-k decode calls"
    Assert-True $header.Contains("app_flow_import_key(") "app_flow.h should expose import flow"
}

function Test-GroupChatTransportInvariants {
    $header = Read-RepoFile "src\app_groups.h"
    $groups = Read-RepoFile "src\app_groups.c"
    $flow = Read-RepoFile "src\app_flow.c"
    $messageFlow = Read-RepoFile "src\app_message_flow.c"

    Assert-True $header.Contains("#define APP_GROUP_MAX_MEMBERS 128") "group chat should allow 128 members"
    Assert-True $header.Contains("#define APP_GROUP_MESSAGE_OVERHEAD_BYTES 31") "group message overhead should remain 31 bytes"
    Assert-True $groups.Contains("#define GROUP_HEADER_BYTES 19") "group message header should be 19 bytes"
    Assert-True $groups.Contains("#define GROUP_TAG_BYTES 12") "group message tag should be 12 bytes"
    Assert-True $groups.Contains("#define GROUPS_VERSION 2u") "group database should version sender display names and aliases"
    Assert-True $groups.Contains("reported_name") "group decrypt should remember sender-provided display names"
    Assert-True $groups.Contains("alias_name") "group state should support local member alias overrides"
    Assert-True $groups.Contains("resolve_member_lookup") "group aliases should resolve by member id or known nickname"
    Assert-True $groups.Contains("current_local_minute_of_day") "group message payload should include a short timestamp"
    Assert-True $groups.Contains("write_file_bytes_atomic") "group database and archive writes should use atomic writes"
    Assert-True $groups.Contains("BOOL app_groups_rekey(") "group chat should support explicit epoch refresh"
    Assert-True $groups.Contains("memcmp(epoch_seed, group->epoch_seed") "same-epoch group package imports should not reset sender chains"
    Assert-True $flow.Contains("app_flow_encrypt_group_message(") "app_flow should expose group encryption orchestration"
    Assert-True $flow.Contains("app_flow_rekey_group_key(") "app_flow should expose group epoch refresh orchestration"
    Assert-True $messageFlow.Contains("app_groups_decrypt_message(") "message flow should try group decrypt before private profile decrypt"
}

function Test-TopLevelCMakeBuildTargets {
    $cmake = Read-RepoFile "CMakeLists.txt"
    $mingw = Read-RepoFile "build-mingw.bat"
    $msvc = Read-RepoFile "build.bat"

    Assert-True $cmake.Contains("add_executable(ChineseInputAgent") "CMakeLists should define ChineseInputAgent"
    Assert-True $cmake.Contains("add_executable(ChineseInputAgentInstallerStub") "CMakeLists should define installer stub"
    Assert-True $cmake.Contains("src/app_flow.c") "CMakeLists should include app_flow.c"
    Assert-True $cmake.Contains("src/app_carrier_flow.c") "CMakeLists should include app_carrier_flow.c"
    Assert-True $cmake.Contains("src/app_contact_flow.c") "CMakeLists should include app_contact_flow.c"
    Assert-True $cmake.Contains("src/app_message_flow.c") "CMakeLists should include app_message_flow.c"
    Assert-True $cmake.Contains("src/app_groups.c") "CMakeLists should include app_groups.c"
    Assert-True $mingw.Contains("cmake.exe -S") "build-mingw.bat should be a CMake wrapper"
    Assert-True $msvc.Contains("cmake.exe -S") "build.bat should be a CMake wrapper"
}

$tests = @(
    "Test-InstallerDownloadsWorkerDefaultModel",
    "Test-DocsDoNotOverstateForwardSecrecy",
    "Test-WorkerResponseIdIsChecked",
    "Test-CryptoBoxUsesOpaqueContext",
    "Test-CryptoBoxUsesSessionTransport",
    "Test-ProfilesDoNotManageCryptoLifecycle",
    "Test-KeyPersistenceUsesAtomicWrites",
    "Test-AppFlowOwnsCryptoBusinessFlow",
    "Test-GroupChatTransportInvariants",
    "Test-TopLevelCMakeBuildTargets"
)

foreach ($test in $tests) {
    & $test
    Write-Host "ok $test"
}
