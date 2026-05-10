#ifndef CHINESE_INPUT_AGENT_APP_INSTALLER_CONFIG_H
#define CHINESE_INPUT_AGENT_APP_INSTALLER_CONFIG_H

typedef struct APP_INSTALL_MODEL_OPTION {
    const WCHAR *label;
    const WCHAR *repo;
    const WCHAR *file_prefix;
} APP_INSTALL_MODEL_OPTION;

typedef struct APP_INSTALL_QUANT_OPTION {
    const WCHAR *label;
    const WCHAR *suffix;
} APP_INSTALL_QUANT_OPTION;

static const APP_INSTALL_MODEL_OPTION APP_INSTALL_MODEL_OPTIONS[] = {
    { L"Qwen3-0.6B（不推荐）", L"unsloth/Qwen3-0.6B-GGUF", L"Qwen3-0.6B" },
    { L"Qwen3-1.7B", L"unsloth/Qwen3-1.7B-GGUF", L"Qwen3-1.7B" },
    { L"Qwen3-4B", L"unsloth/Qwen3-4B-GGUF", L"Qwen3-4B" },
    { L"Qwen3-4B-Instruct-2507", L"unsloth/Qwen3-4B-Instruct-2507-GGUF", L"Qwen3-4B-Instruct-2507" },
    { L"Qwen3-8B", L"unsloth/Qwen3-8B-GGUF", L"Qwen3-8B" },
    { L"Qwen3-14B", L"unsloth/Qwen3-14B-GGUF", L"Qwen3-14B" },
    { L"Qwen3-30B-A3B", L"unsloth/Qwen3-30B-A3B-GGUF", L"Qwen3-30B-A3B" },
    { L"Qwen3-30B-A3B-Instruct-2507", L"unsloth/Qwen3-30B-A3B-Instruct-2507-GGUF", L"Qwen3-30B-A3B-Instruct-2507" },
    { L"Qwen3-32B", L"unsloth/Qwen3-32B-GGUF", L"Qwen3-32B" },
    { L"Qwen3-235B-A22B", L"unsloth/Qwen3-235B-A22B-GGUF", L"Qwen3-235B-A22B" },
    { L"Qwen3-235B-A22B-Instruct-2507", L"unsloth/Qwen3-235B-A22B-Instruct-2507-GGUF", L"Qwen3-235B-A22B-Instruct-2507" },
};

static const APP_INSTALL_QUANT_OPTION APP_INSTALL_QUANT_OPTIONS[] = {
    { L"Q3_K_S", L"Q3_K_S" },
    { L"Q3_K_M", L"Q3_K_M" },
    { L"UD-Q3_K_XL", L"UD-Q3_K_XL" },
    { L"Q4_0", L"Q4_0" },
    { L"Q4_1", L"Q4_1" },
    { L"Q4_K_S", L"Q4_K_S" },
    { L"Q4_K_M", L"Q4_K_M" },
    { L"UD-Q4_K_XL", L"UD-Q4_K_XL" },
    { L"Q5_K_S", L"Q5_K_S" },
    { L"Q5_K_M", L"Q5_K_M" },
    { L"UD-Q5_K_XL", L"UD-Q5_K_XL" },
    { L"Q6_K", L"Q6_K" },
    { L"UD-Q6_K_XL", L"UD-Q6_K_XL" },
    { L"Q8_0", L"Q8_0" },
    { L"UD-Q8_K_XL", L"UD-Q8_K_XL" },
    { L"F16", L"F16" },
};

#define APP_INSTALL_DEFAULT_MODEL_INDEX 3
#define APP_INSTALL_DEFAULT_QUANT_INDEX 7

#endif
