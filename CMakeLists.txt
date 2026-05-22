cmake_minimum_required(VERSION 3.20)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

project(ChineseInputAgent LANGUAGES C CXX RC)
include(ExternalProject)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/build")
foreach(config DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${config} "${CMAKE_SOURCE_DIR}/build")
endforeach()

if(MINGW AND CMAKE_C_COMPILER_AR)
  set(CMAKE_C_CREATE_STATIC_LIBRARY "${CMAKE_C_COMPILER_AR} cr <TARGET> <LINK_FLAGS> <OBJECTS>")
  set(CMAKE_CXX_CREATE_STATIC_LIBRARY "${CMAKE_C_COMPILER_AR} cr <TARGET> <LINK_FLAGS> <OBJECTS>")
  if(CMAKE_C_COMPILER_RANLIB)
    set(CMAKE_C_ARCHIVE_FINISH "${CMAKE_C_COMPILER_RANLIB} <TARGET>")
    set(CMAKE_CXX_ARCHIVE_FINISH "${CMAKE_C_COMPILER_RANLIB} <TARGET>")
  endif()
endif()

set(CIA_CORE_SOURCES
  src/app_shared.c
  src/app_storage.c
  src/app_profiles.c
  src/app_groups.c
  src/app_archive.c
  src/app_chat_history.c
  src/app_llm.c
  src/app_flow.c
  src/app_carrier_flow.c
  src/app_contact_flow.c
  src/app_image_fec.c
  src/app_image_flow.c
  src/app_image_prepare.c
  src/app_image_stego.c
  src/app_message_flow.c
  src/app_tokenizer_prefs.c
  src/cia_core.c
  src/cia_platform_windows.c
  src/crypto_box.c
  third_party/curve25519-donna/curve25519-donna.c
  third_party/sqlite/sqlite3.c
)

set(APP_SOURCES
  src/main.c
  src/app_clipboard_monitor.c
  src/app_work.c
  src/app_attachments.c
  src/ui_key_transfer.c
  src/ui_name_prompt.c
  src/ui_overlay.c
  src/ui_generation_settings.c
  src/ui_tray.c
  src/ui_work_messages.c
  src/win_util.c
  src/app.rc
)

set(ENABLE_SHARED OFF CACHE BOOL "" FORCE)
set(ENABLE_STATIC ON CACHE BOOL "" FORCE)
set(WITH_TURBOJPEG OFF CACHE BOOL "" FORCE)
set(WITH_TOOLS OFF CACHE BOOL "" FORCE)
set(WITH_TESTS OFF CACHE BOOL "" FORCE)
set(WITH_SIMD OFF CACHE BOOL "" FORCE)
set(CIA_JPEG_TURBO_BINARY_DIR "${CMAKE_BINARY_DIR}/third_party/libjpeg-turbo-build")
if(MSVC)
  set(CIA_JPEG_TURBO_LIBRARY "${CIA_JPEG_TURBO_BINARY_DIR}/jpeg-static.lib")
else()
  set(CIA_JPEG_TURBO_LIBRARY "${CIA_JPEG_TURBO_BINARY_DIR}/libjpeg.a")
endif()
ExternalProject_Add(cia_jpeg_turbo_ep
  SOURCE_DIR "${CMAKE_SOURCE_DIR}/third_party/libjpeg-turbo"
  BINARY_DIR "${CIA_JPEG_TURBO_BINARY_DIR}"
  CMAKE_ARGS
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DENABLE_SHARED=OFF
    -DENABLE_STATIC=ON
    -DWITH_TURBOJPEG=OFF
    -DWITH_TOOLS=OFF
    -DWITH_TESTS=OFF
    -DWITH_SIMD=OFF
  BUILD_BYPRODUCTS "${CIA_JPEG_TURBO_LIBRARY}"
  INSTALL_COMMAND ""
)
add_library(cia_jpeg STATIC IMPORTED GLOBAL)
set_target_properties(cia_jpeg PROPERTIES IMPORTED_LOCATION "${CIA_JPEG_TURBO_LIBRARY}")

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(AVIF_CODEC_AOM LOCAL CACHE STRING "" FORCE)
set(AVIF_CODEC_AOM_DECODE ON CACHE BOOL "" FORCE)
set(AVIF_CODEC_AOM_ENCODE ON CACHE BOOL "" FORCE)
set(AVIF_BUILD_APPS OFF CACHE BOOL "" FORCE)
set(AVIF_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(AVIF_LIBYUV OFF CACHE STRING "" FORCE)
set(AVIF_JPEG OFF CACHE STRING "" FORCE)
set(AVIF_ZLIBPNG OFF CACHE STRING "" FORCE)
set(AOM_TARGET_CPU generic CACHE STRING "" FORCE)
set(CONFIG_AV1_DECODER 1 CACHE INTERNAL "" FORCE)
set(CONFIG_AV1_ENCODER 1 CACHE INTERNAL "" FORCE)
set(_CIA_TRY_COMPILE_TARGET_TYPE "${CMAKE_TRY_COMPILE_TARGET_TYPE}")
set(CMAKE_TRY_COMPILE_TARGET_TYPE EXECUTABLE)
add_subdirectory(third_party/libavif EXCLUDE_FROM_ALL)
set(CMAKE_TRY_COMPILE_TARGET_TYPE "${_CIA_TRY_COMPILE_TARGET_TYPE}")

add_library(cia_core STATIC ${CIA_CORE_SOURCES})
target_link_libraries(cia_core PUBLIC
  bcrypt
  crypt32
  ncrypt
  ole32
  windowscodecs
  cia_jpeg
  avif
)
add_dependencies(cia_core cia_jpeg_turbo_ep)

add_executable(ChineseInputAgent WIN32 ${APP_SOURCES})
add_executable(cia_core_smoke_test tools/tests/cia_core_smoke_test.c)
add_executable(image_fec_test tools/tests/image_fec_test.c)

set(CIA_COMMON_COMPILE_DEFINITIONS
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  _CRT_SECURE_NO_WARNINGS
  _WINDOWS
  HAVE_SECUREZEROMEMORY=1
  SQLITE_OMIT_LOAD_EXTENSION
  SQLITE_DEFAULT_MEMSTATUS=0
)

set(CIA_COMMON_INCLUDE_DIRS
  "${CMAKE_SOURCE_DIR}/src"
  "${CMAKE_SOURCE_DIR}/third_party/curve25519-donna"
  "${CMAKE_SOURCE_DIR}/third_party/sqlite"
  "${CMAKE_SOURCE_DIR}/third_party/libjpeg-turbo/src"
  "${CIA_JPEG_TURBO_BINARY_DIR}"
  "${CMAKE_SOURCE_DIR}/third_party/libavif/include"
)

foreach(target cia_core ChineseInputAgent cia_core_smoke_test image_fec_test)
  target_compile_definitions(${target} PRIVATE ${CIA_COMMON_COMPILE_DEFINITIONS})
  target_include_directories(${target} PRIVATE ${CIA_COMMON_INCLUDE_DIRS})
endforeach()

target_link_libraries(cia_core_smoke_test PRIVATE cia_core)
target_link_libraries(image_fec_test PRIVATE cia_core)

target_link_libraries(ChineseInputAgent PRIVATE
  cia_core
  user32
  gdi32
  comctl32
  shell32
  comdlg32
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
  bcrypt
  user32
  gdi32
  comctl32
  shell32
  ole32
)

if(MSVC)
  target_compile_options(cia_core PRIVATE /utf-8 /W3)
  target_compile_options(ChineseInputAgent PRIVATE /utf-8 /W3)
  target_compile_options(cia_core_smoke_test PRIVATE /utf-8 /W3)
  target_compile_options(image_fec_test PRIVATE /utf-8 /W3)
  target_compile_options(ChineseInputAgentInstallerStub PRIVATE /utf-8 /W3)
  # app.rc and installer.rc explicitly embed app.manifest; disable MSVC's generated manifest to avoid duplicates.
  target_link_options(ChineseInputAgent PRIVATE /MANIFEST:NO)
  target_link_options(ChineseInputAgentInstallerStub PRIVATE /MANIFEST:NO)
endif()

if(MINGW)
  target_compile_options(cia_core PRIVATE -finput-charset=UTF-8 -fexec-charset=UTF-8)
  target_compile_options(ChineseInputAgent PRIVATE -finput-charset=UTF-8 -fexec-charset=UTF-8)
  target_compile_options(cia_core_smoke_test PRIVATE -finput-charset=UTF-8 -fexec-charset=UTF-8)
  target_compile_options(image_fec_test PRIVATE -finput-charset=UTF-8 -fexec-charset=UTF-8)
  target_compile_options(ChineseInputAgentInstallerStub PRIVATE -finput-charset=UTF-8 -fexec-charset=UTF-8)
  target_link_options(ChineseInputAgent PRIVATE -municode -static -static-libgcc)
  target_link_options(cia_core_smoke_test PRIVATE -municode -static -static-libgcc)
  target_link_options(image_fec_test PRIVATE -municode -static -static-libgcc)
  target_link_options(ChineseInputAgentInstallerStub PRIVATE -municode -static -static-libgcc)
endif()
