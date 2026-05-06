#ifndef CHINESE_INPUT_AGENT_APP_PATHS_H
#define CHINESE_INPUT_AGENT_APP_PATHS_H

#define APP_ENV_DATA_DIR L"CIA_DATA_DIR"
#define APP_PORTABLE_DATA_DIR_NAME L"data"

#define APP_PROFILES_FILE_NAME L"profiles.dat"
#define APP_PROFILE_STATE_FILE_FORMAT L"state_%s.dat"
#define APP_PROFILE_ARCHIVE_FILE_FORMAT L"archive_%s.dat"
#define APP_PROFILE_LEGACY_ARCHIVE_FILE_FORMAT L"archive_%s.txt"

#define APP_WORKER_TOOLS_DIR L"tools\\payload_watermark"
#define APP_WORKER_PACKAGE_DIR_NAME L"llama_worker_package"
#define APP_WORKER_EXE_NAME L"cia_llama_worker.exe"

#define APP_TEMP_FILE_PREFIX L"cia"

#define APP_INSTALL_SUBDIR_NAME L"ChineseInputAgent"
#define APP_INSTALL_EXE_NAME L"ChineseInputAgent.exe"
#define APP_INSTALL_MODELS_DIR_NAME L"models"
#define APP_INSTALL_MODEL_NAME L"base_model.gguf"
#define APP_INSTALL_TEMP_FILE_FORMAT L"%scia_installer_%lu%s"

#endif
