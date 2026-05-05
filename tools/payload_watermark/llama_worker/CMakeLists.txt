cmake_minimum_required(VERSION 3.20)
project(ChineseInputAgentLlamaWorker C CXX)
add_compile_definitions(_WIN32_WINNT=0x0A00 WINVER=0x0A00)

option(CIA_LLAMA_SHARED_BACKENDS "Build llama.cpp backends as loadable backend DLLs" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

set(LLAMA_BUILD_COMMON ON CACHE BOOL "" FORCE)
set(LLAMA_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_SERVER OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_TOOLS ON CACHE BOOL "" FORCE)
set(LLAMA_CURL OFF CACHE BOOL "" FORCE)
set(LLAMA_OPENSSL OFF CACHE BOOL "" FORCE)
if (CIA_LLAMA_SHARED_BACKENDS)
  set(BUILD_SHARED_LIBS ON CACHE BOOL "" FORCE)
  set(GGML_BACKEND_DL ON CACHE BOOL "" FORCE)
  set(GGML_NATIVE OFF CACHE BOOL "" FORCE)
else()
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
  set(GGML_BACKEND_DL OFF CACHE BOOL "" FORCE)
endif()

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../../third_party/llama.cpp ${CMAKE_BINARY_DIR}/llama.cpp)

add_executable(cia_llama_worker ${CMAKE_CURRENT_LIST_DIR}/../cia_llama_worker.cpp)
target_link_libraries(cia_llama_worker PRIVATE llama)
target_include_directories(cia_llama_worker PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/../../../third_party/llama.cpp/include
  ${CMAKE_CURRENT_LIST_DIR}/../../../third_party/llama.cpp/ggml/include)

if (MINGW AND NOT BUILD_SHARED_LIBS)
  target_compile_options(cia_llama_worker PRIVATE -finput-charset=UTF-8 -fexec-charset=UTF-8)
  target_link_options(cia_llama_worker PRIVATE -static -static-libgcc -static-libstdc++)
elseif(MINGW)
  target_compile_options(cia_llama_worker PRIVATE -finput-charset=UTF-8 -fexec-charset=UTF-8)
elseif(MSVC)
  target_compile_options(cia_llama_worker PRIVATE /utf-8)
endif()
