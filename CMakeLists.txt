cmake_minimum_required(VERSION 3.20)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

project(ChineseInputAgent LANGUAGES C RC)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/build")
foreach(config DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${config} "${CMAKE_SOURCE_DIR}/build")
endforeach()

set(APP_SOURCES
  src/main.c
  src/app_shared.c
  src/app_storage.c
  src/app_profiles.c
  src/app_groups.c
  src/app_archive.c
  src/app_llm.c
  src/app_flow.c
  src/app_carrier_flow.c
  src/app_contact_flow.c
  src/app_message_flow.c
  src/app_tokenizer_prefs.c
  src/app_work.c
  src/ui_key_transfer.c
  src/ui_name_prompt.c
  src/ui_overlay.c
  src/ui_work_messages.c
  src/win_util.c
  src/crypto_box.c
  third_party/curve25519-donna/curve25519-donna.c
  src/app.rc
)

add_executable(ChineseInputAgent WIN32 ${APP_SOURCES})
target_compile_definitions(ChineseInputAgent PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  _CRT_SECURE_NO_WARNINGS
  _WINDOWS
  HAVE_SECUREZEROMEMORY=1
)
target_include_directories(ChineseInputAgent PRIVATE
  "${CMAKE_SOURCE_DIR}/src"
  "${CMAKE_SOURCE_DIR}/third_party/curve25519-donna"
)
target_link_libraries(ChineseInputAgent PRIVATE
  user32
  gdi32
  comctl32
  advapi32
  crypt32
  bcrypt
  ncrypt
  shell32
)

add_executable(ChineseInputAgentInstallerStub WIN32
  src/installer.c
  src/installer.rc
)
target_compile_definitions(ChineseInputAgentInstallerStub PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  _CRT_SECURE_NO_WARNINGS
  _WINDOWS
)
target_include_directories(ChineseInputAgentInstallerStub PRIVATE
  "${CMAKE_SOURCE_DIR}/src"
)
target_link_libraries(ChineseInputAgentInstallerStub PRIVATE
  user32
  gdi32
  comctl32
  shell32
  ole32
)

if(MSVC)
  target_compile_options(ChineseInputAgent PRIVATE /utf-8 /W3)
  target_compile_options(ChineseInputAgentInstallerStub PRIVATE /utf-8 /W3)
  # app.rc and installer.rc explicitly embed app.manifest; disable MSVC's generated manifest to avoid duplicates.
  target_link_options(ChineseInputAgent PRIVATE /MANIFEST:NO)
  target_link_options(ChineseInputAgentInstallerStub PRIVATE /MANIFEST:NO)
endif()

if(MINGW)
  target_compile_options(ChineseInputAgent PRIVATE -finput-charset=UTF-8 -fexec-charset=UTF-8)
  target_compile_options(ChineseInputAgentInstallerStub PRIVATE -finput-charset=UTF-8 -fexec-charset=UTF-8)
  target_link_options(ChineseInputAgent PRIVATE -municode -static -static-libgcc)
  target_link_options(ChineseInputAgentInstallerStub PRIVATE -municode -static -static-libgcc)
endif()
