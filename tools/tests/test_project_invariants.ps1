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
    Assert-True $installerConfig.Contains("Qwen3-4B-Instruct-2507-GGUF") "installer should download the stable release model, not the experimental 2B model"
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

function Test-WorkerPromptsAreRuntimeFiles {
    $workerCpp = Read-RepoFile "tools\payload_watermark\cia_llama_worker.cpp"
    $packageBat = Read-RepoFile "package-mingw.bat"
    $workerBat = Read-RepoFile "build-llama-worker.bat"
    $workerConfig = Read-RepoFile "tools\payload_watermark\worker_config.txt"
    $defaultPrompt = Read-RepoFile "tools\payload_watermark\prompts\default.txt"
    $selfIntroPrompt = Read-RepoFile "tools\payload_watermark\prompts\self_intro.txt"
    $groupKeyPrompt = Read-RepoFile "tools\payload_watermark\prompts\group_key.txt"
    $outlinePrompt = Read-RepoFile "tools\payload_watermark\prompts\outline.txt"
    $rejectPhrases = Read-RepoFile "tools\payload_watermark\prompts\reject_phrases.txt"

    Assert-True $workerCpp.Contains("load_prompt_template(") "worker should load carrier prompts from runtime template files"
    Assert-True $workerCpp.Contains("--prompt-dir") "worker should allow overriding the runtime prompt directory"
    Assert-True $workerCpp.Contains("--config") "worker should allow overriding runtime worker config"
    Assert-True $workerCpp.Contains("--tokenizer-dir") "worker should allow overriding runtime tokenizer assets"
    Assert-True $workerCpp.Contains("decode_multi") "worker should expose multi-tokenizer carrier decode"
    Assert-True $workerCpp.Contains("CIA_PROMPT_DIR") "worker should allow prompt directory override via environment"
    Assert-True $workerCpp.Contains("CIA_WORKER_CONFIG") "worker should allow worker config override via environment"
    Assert-True $workerCpp.Contains("CIA_TOKENIZER_DIR") "worker should allow tokenizer directory override via environment"
    Assert-True $defaultPrompt.Contains("{topic}") "default prompt should expose the topic placeholder"
    Assert-True $defaultPrompt.Contains("{length_requirement}") "default prompt should include the dynamic length requirement"
    Assert-True $selfIntroPrompt.Contains("{length_requirement}") "self-introduction prompt should include the dynamic length requirement"
    Assert-True $groupKeyPrompt.Contains("{length_requirement}") "group key prompt should include the dynamic length requirement"
    Assert-True $workerConfig.Contains("outline_enabled=0") "worker outline pass should be disabled by runtime worker_config.txt"
    Assert-True (-not $defaultPrompt.Contains("{outline}")) "default prompt should not depend on outline text when outline is disabled"
    Assert-True (-not $selfIntroPrompt.Contains("{outline}")) "self-introduction prompt should not depend on outline text when outline is disabled"
    Assert-True (-not $groupKeyPrompt.Contains("{outline}")) "group key prompt should not depend on outline text when outline is disabled"
    Assert-True $outlinePrompt.Contains("{prompt_template}") "outline prompt should know which content template is being generated"
    Assert-True $outlinePrompt.Contains("{length_requirement}") "outline prompt should include the dynamic length target"
    Assert-True $defaultPrompt.Contains("/no_think") "default prompt should request Qwen non-thinking output"
    Assert-True $selfIntroPrompt.Contains("/no_think") "self-introduction prompt should request Qwen non-thinking output"
    Assert-True $groupKeyPrompt.Contains("/no_think") "group key prompt should request Qwen non-thinking output"
    Assert-True (-not [regex]::IsMatch($defaultPrompt, '<\|im_start\|>assistant\s*<think>')) "default prompt should not prefill a Qwen think block"
    Assert-True $defaultPrompt.Contains("<|im_start|>system") "default prompt should use a Qwen-style system/user chat template"
    Assert-True ($rejectPhrases.Length -gt 100) "reject phrase list should be editable without rebuilding worker"
    Assert-True $workerConfig.Contains("temperature=0.7") "Qwen3 non-thinking sampling defaults should live in runtime worker_config.txt"
    Assert-True $workerConfig.Contains("top_p=0.8") "Qwen3 non-thinking top-p default should live in runtime worker_config.txt"
    Assert-True $workerConfig.Contains("top_k=128") "Qwen3 carrier top-k default should live in runtime worker_config.txt"
    Assert-True $workerConfig.Contains("max_tail_tokens=64") "worker free-tail clamp should live in runtime worker_config.txt"
    Assert-True $workerConfig.Contains("length_payload_multiplier=") "worker length scaling should live in runtime worker_config.txt"
    Assert-True $workerConfig.Contains("encode_attempts=") "worker retry count should live in runtime worker_config.txt"
    Assert-True $workerConfig.Contains("outline_enabled=0") "worker outline pass should be controlled by runtime worker_config.txt"
    Assert-True $workerConfig.Contains("outline_tokens=") "worker outline token budget should live in runtime worker_config.txt"
    Assert-True $workerConfig.Contains("model=base_model.gguf") "default release model name should live in runtime worker_config.txt"
    Assert-True $workerConfig.Contains("tokenizer_id=") "current model tokenizer id should live in runtime worker_config.txt"
    Assert-True $workerConfig.Contains("decode_tokenizers=") "decode tokenizer list should live in runtime worker_config.txt"
    Assert-True $workerConfig.Contains("decode_threads=") "multi-tokenizer decode thread count should live in runtime worker_config.txt"
    Assert-True $packageBat.Contains("tools\payload_watermark\prompts") "portable packaging should include runtime prompt templates"
    Assert-True $packageBat.Contains("tools\payload_watermark\tokenizers") "portable packaging should include staged tokenizer assets when present"
    Assert-True $packageBat.Contains("worker_config.txt") "portable packaging should include runtime worker config"
    Assert-True $workerBat.Contains(":stage_prompts") "worker packaging should stage runtime prompt templates"
    Assert-True $workerBat.Contains(":stage_tokenizers") "worker packaging should stage runtime tokenizer assets"
    Assert-True $workerBat.Contains("worker_config.txt") "worker packaging should stage runtime worker config"
}

function Test-CryptoBoxUsesOpaqueContext {
    $header = Read-RepoFile "src\crypto_box.h"
    $impl = Read-RepoFile "src\crypto_box.c"

    Assert-True $header.Contains("typedef struct CRYPTO_BOX CRYPTO_BOX;") "crypto_box.h should expose CRYPTO_BOX as an opaque context"
    Assert-True $header.Contains("crypto_box_open(") "crypto_box.h should expose crypto_box_open"
    Assert-True $header.Contains("state_encryption_key") "crypto_box_open should accept a state encryption key, not a profile master key"
    Assert-True $header.Contains("crypto_box_close(") "crypto_box.h should expose crypto_box_close"
    Assert-True $header.Contains("crypto_box_encrypt(CRYPTO_BOX *box") "crypto_box_encrypt should take an explicit context"
    Assert-True $header.Contains("crypto_box_decrypt(CRYPTO_BOX *box") "crypto_box_decrypt should take an explicit context"
    Assert-True (-not $header.Contains("crypto_box_init(")) "crypto_box_init should not remain in the public API"
    Assert-True (-not $header.Contains("crypto_box_shutdown(")) "crypto_box_shutdown should not remain in the public API"
    Assert-True $impl.Contains("struct CRYPTO_BOX") "crypto_box.c should own the CRYPTO_BOX layout"
    Assert-True $impl.Contains("BYTE state_key[STATE_KEY_BYTES]") "CRYPTO_BOX should store only the state encryption key"
    Assert-True (-not $impl.Contains("master_key")) "crypto_box.c should not name or store a profile master key"
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
    Assert-True $header.Contains("profiles_with_private_history_key(") "app_profiles.h should expose a narrow private history key helper"
    Assert-True (-not $header.Contains("profiles_with_master_key(")) "app_profiles.h should not expose a general profile root-key lease"
    Assert-True $profiles.Contains("lock_profile_master(&g_profiles[profile_idx])") "inactive profile master keys should be securely cleared"
    Assert-True $profiles.Contains("PROFILE_KEY_LABEL_CRYPTO_STATE") "profiles layer should derive a dedicated crypto state key"
    Assert-True $profiles.Contains("PROFILE_KEY_LABEL_PRIVATE_HISTORY") "profiles layer should derive a dedicated private history key"
    Assert-True $profiles.Contains("lock_profile_master_if_inactive(index)") "profiles_open_crypto should clear non-active root keys internally"
    Assert-True (-not $activate.Contains("crypto_box_init")) "profiles_activate should not initialize crypto_box"
    Assert-True (-not $activate.Contains("crypto_box_shutdown")) "profiles_activate should not shut down crypto_box"
    Assert-True (-not $activate.Contains("crypto_box_export_contact_package")) "profiles_activate should not export crypto material"
    Assert-True (-not $profiles.Contains("profiles_build_key_package")) "profile layer should not build key packages"
}

function Test-KeyPersistenceUsesAtomicWrites {
    $shared = Read-RepoFile "src\app_shared.c"
    $platform = Read-RepoFile "src\cia_platform_windows.c"
    $profiles = Read-RepoFile "src\app_profiles.c"
    $archive = Read-RepoFile "src\app_archive.c"
    $chatHistory = Read-RepoFile "src\app_chat_history.c"
    $crypto = Read-RepoFile "src\crypto_box.c"

    Assert-True $shared.Contains("write_file_bytes_atomic") "app_shared.c should implement write_file_bytes_atomic"
    Assert-True $shared.Contains("cia_win_write_file_bytes_atomic") "app_shared atomic writes should delegate to the platform boundary"
    Assert-True $platform.Contains("MoveFileExW") "atomic writes should replace via MoveFileExW"
    Assert-True $platform.Contains("MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH") "atomic writes should use replace and write-through"
    Assert-True (Get-RepoSlice $profiles "BOOL profiles_save" "BOOL profiles_create_from_master").Contains("write_file_bytes_atomic") "profiles_save should use atomic writes"
    Assert-True $archive.Contains("chat_history_append_private") "private archive append should delegate to SQLite chat history"
    Assert-True $archive.Contains("chat_history_load_private") "private archive load should delegate to SQLite chat history"
    Assert-True (-not $archive.Contains("profiles_get_archive_path_by_index")) "private archive adapter should not read legacy archive paths"
    Assert-True $chatHistory.Contains("BEGIN IMMEDIATE TRANSACTION") "chat history append should use a SQLite transaction"
    Assert-True $chatHistory.Contains("ROLLBACK") "chat history append failure should roll back the SQLite transaction"
    Assert-True (Get-RepoSlice $crypto "static BOOL write_file_all" "static BOOL box_file_exists").Contains("write_file_bytes_atomic") "crypto state save should use atomic writes"
}

function Test-ChatHistoryUsesEncryptedRowsInSQLite {
    $cmake = Read-RepoFile "CMakeLists.txt"
    $paths = Read-RepoFile "src\app_paths.h"
    $header = Read-RepoFile "src\app_chat_history.h"
    $history = Read-RepoFile "src\app_chat_history.c"
    $archive = Read-RepoFile "src\app_archive.c"
    $groups = Read-RepoFile "src\app_groups.c"
    $profiles = Read-RepoFile "src\app_profiles.c"

    Assert-True $cmake.Contains("src/app_chat_history.c") "CMakeLists should include app_chat_history.c"
    Assert-True $cmake.Contains("third_party/sqlite/sqlite3.c") "CMakeLists should compile SQLite amalgamation"
    Assert-True $cmake.Contains("SQLITE_OMIT_LOAD_EXTENSION") "SQLite extension loading should be omitted"
    Assert-True $cmake.Contains("SQLITE_DEFAULT_MEMSTATUS=0") "SQLite memory status should be disabled"
    Assert-True $paths.Contains("APP_CHAT_HISTORY_DB_NAME L`"chat_history.db`"") "chat history DB file name should be centralized"
    Assert-True $header.Contains("chat_history_append_private") "chat history module should expose private append"
    Assert-True $header.Contains("chat_history_load_private") "chat history module should expose private load"
    Assert-True $header.Contains("chat_history_append_group") "chat history module should expose group append"
    Assert-True $header.Contains("chat_history_load_group") "chat history module should expose group load"
    Assert-True (-not $history.Contains('#include "app_profiles.h"')) "chat history module should not depend on profiles"
    Assert-True (-not $history.Contains('#include "app_groups.h"')) "chat history module should not depend on groups"
    Assert-True $history.Contains("CREATE TABLE IF NOT EXISTS messages") "chat history should create the messages table"
    Assert-True $history.Contains("group_history_keys") "chat history should store local wrapped group history keys"
    Assert-True $history.Contains("BCRYPT_CHAIN_MODE_GCM") "chat history rows should use AES-GCM"
    Assert-True $history.Contains("#define CHAT_TAG_BYTES 16") "chat history AES-GCM tag should remain 16 bytes"
    Assert-True $history.Contains("cia_win_dpapi_protect") "group history keys should be protected by DPAPI through the platform boundary"
    Assert-True $history.Contains("cia_win_dpapi_unprotect") "group history keys should be unprotected by DPAPI through the platform boundary"
    Assert-True $history.Contains("group_history_key_entropy") "group history key DPAPI protection should be scoped to the group id"
    Assert-True $history.Contains("PRAGMA secure_delete=ON") "SQLite should enable secure_delete"
    Assert-True $history.Contains("verify_schema_version") "chat history should reject unsupported schema versions"
    Assert-True $history.Contains("Unsupported chat history schema version") "schema mismatch should return a clear error"
    Assert-True $profiles.Contains("hmac_sha256_segments") "private history keys should be derived by HMAC-SHA256 in the profiles layer"
    Assert-True (-not $history.Contains("derive_private_history_key")) "chat history should receive a derived key instead of deriving from the profile root key"
    Assert-True $history.Contains("message_uuid BLOB NOT NULL UNIQUE") "chat history rows should have unique message UUIDs"
    Assert-True $history.Contains("ciphertext BLOB NOT NULL") "chat history body should be stored as ciphertext"
    Assert-True $history.Contains("timestamp_text") "chat history display timestamps should remain stored metadata"
    Assert-True $archive.Contains("chat_history_append_private") "private archive adapter should use chat history append"
    Assert-True $archive.Contains("profiles_with_private_history_key") "private archive adapter should not request the profile root key"
    Assert-True (-not $archive.Contains("profiles_with_master_key")) "private archive adapter should not touch the profile root key"
    Assert-True $groups.Contains("chat_history_append_group") "group archive adapter should use chat history append"
    Assert-True (-not $groups.Contains("group_archive_path")) "group archive adapter should not use legacy archive files"
}

function Test-AppFlowOwnsCryptoBusinessFlow {
    $main = Read-RepoFile "src\main.c"
    $work = Read-RepoFile "src\app_work.c"
    $flow = Read-RepoFile "src\app_flow.c"
    $messageFlow = Read-RepoFile "src\app_message_flow.c"
    $contactFlow = Read-RepoFile "src\app_contact_flow.c"
    $carrierFlow = Read-RepoFile "src\app_carrier_flow.c"
    $header = Read-RepoFile "src\app_flow.h"
    $carrierHeader = Read-RepoFile "src\app_carrier_flow.h"
    $llmHeader = Read-RepoFile "src\app_llm.h"
    $progressHeader = Read-RepoFile "src\app_progress.h"

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
    Assert-True ($messageFlow.Contains("app_groups_decrypt_message(") -or $messageFlow.Contains("app_groups_decrypt_message_ex(")) "app_message_flow.c should own group/private decrypt routing"
    Assert-True $contactFlow.Contains("crypto_box_import_contact_package(") "app_contact_flow.c should own contact key import orchestration"
    Assert-True $contactFlow.Contains("crypto_box_export_contact_package(") "app_contact_flow.c should own contact key export orchestration"
    Assert-True $carrierFlow.Contains("local_topk_encode_payload(") "app_carrier_flow.c should own top-k encode calls"
    Assert-True $carrierFlow.Contains("local_topk_decode_payload(") "app_carrier_flow.c should own top-k decode calls"
    Assert-True $carrierFlow.Contains("local_topk_decode_payload_multi(") "app_carrier_flow.c should expose multi-tokenizer decode calls"
    Assert-True $contactFlow.Contains("app_carrier_decode_exchange_package_multi(") "contact key import should try all configured tokenizers"
    Assert-True $header.Contains("app_flow_import_key(") "app_flow.h should expose import flow"
    Assert-True $progressHeader.Contains("typedef struct CIA_PROGRESS_SINK") "core should expose a generic progress sink"
    Assert-True (-not $header.Contains("HWND progress_target")) "app_flow.h should not expose HWND progress targets"
    Assert-True (-not $carrierHeader.Contains("HWND progress_target")) "app_carrier_flow.h should not expose HWND progress targets"
    Assert-True (-not $llmHeader.Contains("HWND progress_target")) "app_llm.h should not expose HWND progress targets"
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
    Assert-True $groups.Contains("write_file_bytes_atomic") "group database writes should use atomic writes"
    Assert-True $groups.Contains("BOOL app_groups_rekey(") "group chat should support explicit epoch refresh"
    Assert-True $groups.Contains("memcmp(epoch_seed, group->epoch_seed") "same-epoch group package imports should not reset sender chains"
    Assert-True $flow.Contains("app_flow_encrypt_group_message(") "app_flow should expose group encryption orchestration"
    Assert-True $flow.Contains("app_flow_rekey_group_key(") "app_flow should expose group epoch refresh orchestration"
    Assert-True ($messageFlow.Contains("app_groups_decrypt_message(") -or $messageFlow.Contains("app_groups_decrypt_message_ex(")) "message flow should try group decrypt before private profile decrypt"
}

function Test-CiaCoreFacade {
    $cmake = Read-RepoFile "CMakeLists.txt"
    $header = Read-RepoFile "src\cia_core.h"
    $impl = Read-RepoFile "src\cia_core.c"
    $testBat = Read-RepoFile "test.bat"
    $smokeScript = Read-RepoFile "tools\tests\test_cia_core_smoke.ps1"

    Assert-True $cmake.Contains("src/cia_core.c") "cia_core facade should be compiled into the core static library"
    Assert-True $header.Contains("BOOL cia_core_init(") "cia_core.h should expose init"
    Assert-True $header.Contains("void cia_core_cleanup(") "cia_core.h should expose cleanup"
    Assert-True $header.Contains("cia_core_encrypt_message(") "cia_core.h should expose private message encryption"
    Assert-True $header.Contains("cia_core_decrypt_text(") "cia_core.h should expose text decryption"
    Assert-True $header.Contains("cia_core_export_contact(") "cia_core.h should expose contact export"
    Assert-True $header.Contains("cia_core_import_contact(") "cia_core.h should expose contact import"
    Assert-True $header.Contains("cia_core_create_group(") "cia_core.h should expose group creation"
    Assert-True $header.Contains("cia_core_encrypt_group_message(") "cia_core.h should expose group message encryption"
    Assert-True $header.Contains("cia_core_load_chat_history(") "cia_core.h should expose chat history load"
    Assert-True $header.Contains("cia_core_append_chat_history(") "cia_core.h should expose chat history append"
    foreach ($uiToken in @("HWND", "MessageBox", "PostMessage", "WM_APP", "WndProc", "textbox")) {
        Assert-True (-not $header.Contains($uiToken)) "cia_core.h should not expose UI token: $uiToken"
    }
    Assert-True $impl.Contains("app_flow_encrypt_message(") "cia_core.c should reuse app_flow for encryption"
    Assert-True $impl.Contains("app_flow_decrypt_clip_auto(") "cia_core.c should reuse app_flow for decrypt"
    Assert-True $impl.Contains("archive_load_text(") "cia_core.c should reuse archive adapter for private history"
    Assert-True $impl.Contains("app_groups_archive_load_text(") "cia_core.c should reuse group archive adapter"
    Assert-True $testBat.Contains("test_cia_core_smoke.ps1") "test.bat should run the headless cia_core smoke test"
    Assert-True $cmake.Contains("add_executable(cia_core_smoke_test tools/tests/cia_core_smoke_test.c)") "CMake should define a headless cia_core smoke test target"
    Assert-True $cmake.Contains("target_link_libraries(cia_core_smoke_test PRIVATE cia_core)") "cia_core smoke test should link cia_core target"
    Assert-True $cmake.Contains("target_link_libraries(cia_core PUBLIC") "cia_core should export its platform/crypto link dependencies"
    foreach ($coreLib in @("bcrypt", "crypt32", "ncrypt")) {
        Assert-True $cmake.Contains("  $coreLib") "cia_core should export link library: $coreLib"
    }
    Assert-True $smokeScript.Contains('$forbiddenSources') "cia_core smoke test should explicitly guard against linking UI sources"
    Assert-True $smokeScript.Contains('$coreSources -contains $forbidden') "cia_core smoke test should reject UI source entries"
    Assert-True $smokeScript.Contains("--target cia_core_smoke_test") "cia_core smoke script should build the CMake smoke target"
}

function Test-WindowsPlatformBoundary {
    $cmake = Read-RepoFile "CMakeLists.txt"
    $platformHeader = Read-RepoFile "src\cia_platform_windows.h"
    $platformImpl = Read-RepoFile "src\cia_platform_windows.c"
    $storage = Read-RepoFile "src\app_storage.c"
    $shared = Read-RepoFile "src\app_shared.c"
    $history = Read-RepoFile "src\app_chat_history.c"

    Assert-True $cmake.Contains("src/cia_platform_windows.c") "Windows platform boundary should be compiled into cia_core"
    Assert-True $platformHeader.Contains("cia_win_random_bytes") "platform boundary should expose random bytes"
    Assert-True $platformHeader.Contains("cia_win_secure_zero") "platform boundary should expose secure zero"
    Assert-True $platformHeader.Contains("cia_win_write_file_bytes_atomic") "platform boundary should expose atomic file replace"
    Assert-True $platformHeader.Contains("cia_win_dpapi_protect") "platform boundary should expose DPAPI protect"
    Assert-True $platformHeader.Contains("cia_win_dpapi_unprotect") "platform boundary should expose DPAPI unprotect"
    Assert-True $platformImpl.Contains("BCryptGenRandom") "Windows random should be isolated in the platform boundary"
    Assert-True $platformImpl.Contains("CryptProtectData") "DPAPI protect should be isolated in the platform boundary"
    Assert-True $platformImpl.Contains("MoveFileExW") "atomic replace should be isolated in the platform boundary"
    Assert-True $storage.Contains("cia_win_dpapi_protect") "app_storage should use the platform DPAPI wrapper"
    Assert-True $storage.Contains("cia_win_random_bytes") "app_storage should use the platform random wrapper"
    Assert-True $shared.Contains("cia_win_write_file_bytes_atomic") "app_shared atomic write should delegate to platform"
    Assert-True $history.Contains("cia_win_dpapi_protect") "group history DPAPI should use platform wrapper"
}

function Test-TopLevelCMakeBuildTargets {
    $cmake = Read-RepoFile "CMakeLists.txt"
    $mingw = Read-RepoFile "build-mingw.bat"
    $msvc = Read-RepoFile "build.bat"

    Assert-True $cmake.Contains("add_library(cia_core STATIC") "CMakeLists should define cia_core as a static library"
    Assert-True $cmake.Contains("add_executable(cia_core_smoke_test") "CMakeLists should define the headless cia_core smoke test target"
    Assert-True $cmake.Contains("add_executable(ChineseInputAgent") "CMakeLists should define ChineseInputAgent"
    Assert-True $cmake.Contains("add_executable(ChineseInputAgentInstallerStub") "CMakeLists should define installer stub"
    Assert-True $cmake.Contains("target_link_libraries(ChineseInputAgent PRIVATE") "ChineseInputAgent should have an explicit link block"
    Assert-True $cmake.Contains("  cia_core") "ChineseInputAgent should link cia_core"
    Assert-True $cmake.Contains("set(CIA_CORE_SOURCES") "CMakeLists should keep core sources separate from UI sources"
    Assert-True $cmake.Contains("set(APP_SOURCES") "CMakeLists should keep UI executable sources separate"
    Assert-True $cmake.Contains("src/app_flow.c") "CMakeLists should include app_flow.c"
    Assert-True $cmake.Contains("src/app_carrier_flow.c") "CMakeLists should include app_carrier_flow.c"
    Assert-True $cmake.Contains("src/app_contact_flow.c") "CMakeLists should include app_contact_flow.c"
    Assert-True $cmake.Contains("src/app_message_flow.c") "CMakeLists should include app_message_flow.c"
    Assert-True $cmake.Contains("src/app_groups.c") "CMakeLists should include app_groups.c"
    Assert-True $cmake.Contains("src/app_chat_history.c") "CMakeLists should include app_chat_history.c"
    Assert-True $cmake.Contains("third_party/sqlite/sqlite3.c") "CMakeLists should include SQLite amalgamation"
    Assert-True $cmake.Contains("src/app_work.c") "CMakeLists should keep app_work.c in the UI executable"
    Assert-True $cmake.Contains("src/app.rc") "CMakeLists should keep app.rc in the UI executable"
    Assert-True $mingw.Contains("cmake.exe -S") "build-mingw.bat should be a CMake wrapper"
    Assert-True $mingw.Contains("CMAKE_C_COMPILER_AR") "build-mingw.bat should configure the static library archiver"
    Assert-True $mingw.Contains("CMAKE_C_COMPILER_RANLIB") "build-mingw.bat should configure the static library ranlib tool"
    Assert-True $msvc.Contains("cmake.exe -S") "build.bat should be a CMake wrapper"
}

$tests = @(
    "Test-InstallerDownloadsWorkerDefaultModel",
    "Test-DocsDoNotOverstateForwardSecrecy",
    "Test-WorkerResponseIdIsChecked",
    "Test-WorkerPromptsAreRuntimeFiles",
    "Test-CryptoBoxUsesOpaqueContext",
    "Test-CryptoBoxUsesSessionTransport",
    "Test-ProfilesDoNotManageCryptoLifecycle",
    "Test-KeyPersistenceUsesAtomicWrites",
    "Test-ChatHistoryUsesEncryptedRowsInSQLite",
    "Test-AppFlowOwnsCryptoBusinessFlow",
    "Test-GroupChatTransportInvariants",
    "Test-CiaCoreFacade",
    "Test-WindowsPlatformBoundary",
    "Test-TopLevelCMakeBuildTargets"
)

foreach ($test in $tests) {
    & $test
    Write-Host "ok $test"
}
