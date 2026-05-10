#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <strsafe.h>

#include "app_installer_config.h"
#include "app_limits.h"
#include "app_paths.h"
#include "ui_ids.h"

#define CIA_INSTALLER_TITLE L"ChineseInputAgent Portable 安装器"
#define WM_APP_INSTALL_STATUS (WM_APP + 1)
#define WM_APP_INSTALL_DONE (WM_APP + 2)
#define INSTALLER_WINDOW_CLASS_NAME L"ChineseInputAgentInstallerWindow"
/* Installer payload trailer format. Keep this stable for packaged installers. */
static const unsigned char PAYLOAD_MAGIC[16] = {
    'C','I','A','I','N','S','T','P','K','G','0','0','0','1','\r','\n'
};

#pragma pack(push, 1)
typedef struct PAYLOAD_TRAILER {
    unsigned char magic[16];
    uint64_t offset;
    uint64_t size;
} PAYLOAD_TRAILER;
#pragma pack(pop)

typedef struct INSTALL_CTX {
    WCHAR target[MAX_PATH];
    BOOL launch_after;
    int model_index;
    int quant_index;
} INSTALL_CTX;

static HINSTANCE g_instance;
static HWND g_path_edit;
static HWND g_status;
static HWND g_progress;
static HWND g_install_button;
static HWND g_close_button;
static HWND g_launch_check;
static HWND g_model_combo;
static HWND g_quant_combo;
static HFONT g_font;

static void *xalloc(SIZE_T bytes) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes ? bytes : 1);
}

static void xfree(void *ptr) {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

static WCHAR *dup_wide(const WCHAR *text) {
    size_t len = wcslen(text ? text : L"");
    if (len > SIZE_MAX / sizeof(WCHAR) - 1) return NULL;
    WCHAR *copy = (WCHAR *)xalloc((len + 1) * sizeof(WCHAR));
    if (copy) CopyMemory(copy, text ? text : L"", (len + 1) * sizeof(WCHAR));
    return copy;
}

static void set_font(HWND hwnd) {
    if (!hwnd) return;
    SendMessageW(hwnd, WM_SETFONT, (WPARAM)g_font, TRUE);
}

static int clamp_combo_index(int index, int count, int fallback) {
    return (index >= 0 && index < count) ? index : fallback;
}

static const APP_INSTALL_MODEL_OPTION *install_model_option(int index) {
    int safe_index = clamp_combo_index(index, (int)ARRAYSIZE(APP_INSTALL_MODEL_OPTIONS), APP_INSTALL_DEFAULT_MODEL_INDEX);
    return &APP_INSTALL_MODEL_OPTIONS[safe_index];
}

static const APP_INSTALL_QUANT_OPTION *install_quant_option(int index) {
    int safe_index = clamp_combo_index(index, (int)ARRAYSIZE(APP_INSTALL_QUANT_OPTIONS), APP_INSTALL_DEFAULT_QUANT_INDEX);
    return &APP_INSTALL_QUANT_OPTIONS[safe_index];
}

static void populate_install_option_combos(void) {
    for (size_t i = 0; i < ARRAYSIZE(APP_INSTALL_MODEL_OPTIONS); ++i) {
        SendMessageW(g_model_combo, CB_ADDSTRING, 0, (LPARAM)APP_INSTALL_MODEL_OPTIONS[i].label);
    }
    for (size_t i = 0; i < ARRAYSIZE(APP_INSTALL_QUANT_OPTIONS); ++i) {
        SendMessageW(g_quant_combo, CB_ADDSTRING, 0, (LPARAM)APP_INSTALL_QUANT_OPTIONS[i].label);
    }
    SendMessageW(g_model_combo, CB_SETCURSEL, APP_INSTALL_DEFAULT_MODEL_INDEX, 0);
    SendMessageW(g_quant_combo, CB_SETCURSEL, APP_INSTALL_DEFAULT_QUANT_INDEX, 0);
}

static void set_install_controls_enabled(BOOL enabled) {
    EnableWindow(g_install_button, enabled);
    EnableWindow(g_close_button, enabled);
    EnableWindow(g_path_edit, enabled);
    EnableWindow(GetDlgItem(GetParent(g_path_edit), IDC_INSTALLER_BROWSE), enabled);
    EnableWindow(g_model_combo, enabled);
    EnableWindow(g_quant_combo, enabled);
    EnableWindow(g_launch_check, enabled);
}

static BOOL directory_has_gguf(const WCHAR *dir) {
    WCHAR pattern[MAX_PATH];
    if (FAILED(StringCchPrintfW(pattern, ARRAYSIZE(pattern), L"%s\\*.gguf", dir ? dir : L""))) return FALSE;
    WIN32_FIND_DATAW fd;
    HANDLE find = FindFirstFileW(pattern, &fd);
    if (find == INVALID_HANDLE_VALUE) return FALSE;
    BOOL found = FALSE;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            found = TRUE;
            break;
        }
    } while (FindNextFileW(find, &fd));
    FindClose(find);
    return found;
}

static void post_status(int pos, const WCHAR *text) {
    WCHAR *copy = dup_wide(text ? text : L"");
    if (!copy || !PostMessageW(GetParent(g_status), WM_APP_INSTALL_STATUS, (WPARAM)pos, (LPARAM)copy)) {
        xfree(copy);
    }
}

static void post_done(BOOL install_succeeded, const WCHAR *text) {
    WCHAR *copy = dup_wide(text ? text : L"");
    if (!copy || !PostMessageW(GetParent(g_status), WM_APP_INSTALL_DONE, (WPARAM)install_succeeded, (LPARAM)copy)) {
        xfree(copy);
    }
}

static BOOL join_path(WCHAR *out, size_t cch, const WCHAR *base, const WCHAR *leaf) {
    size_t len = wcslen(base ? base : L"");
    const WCHAR *sep = (len && base[len - 1] != L'\\' && base[len - 1] != L'/') ? L"\\" : L"";
    return SUCCEEDED(StringCchPrintfW(out, cch, L"%s%s%s", base ? base : L"", sep, leaf ? leaf : L""));
}

static void strip_last_path_component(WCHAR *path) {
    if (!path) return;
    size_t len = wcslen(path);
    while (len > 0 && (path[len - 1] == L'\\' || path[len - 1] == L'/')) path[--len] = L'\0';
    WCHAR *last_backslash = wcsrchr(path, L'\\');
    WCHAR *last_slash = wcsrchr(path, L'/');
    WCHAR *last = last_backslash;
    if (!last || (last_slash && last_slash > last)) last = last_slash;
    if (last) *last = L'\0';
}

static void default_install_path(WCHAR *out, size_t cch) {
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", out, (DWORD)cch);
    if (got == 0 || got >= cch) {
        got = GetEnvironmentVariableW(L"USERPROFILE", out, (DWORD)cch);
    }
    if (got == 0 || got >= cch) {
        WCHAR exe[MAX_PATH];
        if (GetModuleFileNameW(NULL, exe, ARRAYSIZE(exe))) {
            strip_last_path_component(exe);
            if (join_path(out, cch, exe, APP_INSTALL_SUBDIR_NAME)) return;
        }
        StringCchCopyW(out, cch, APP_INSTALL_SUBDIR_NAME);
        return;
    }
    WCHAR base_path[MAX_PATH];
    StringCchCopyW(base_path, ARRAYSIZE(base_path), out);
    join_path(out, cch, base_path, APP_INSTALL_SUBDIR_NAME);
}

static BOOL ensure_directory(const WCHAR *path, WCHAR *err, size_t err_cch) {
    int rc = SHCreateDirectoryExW(NULL, path, NULL);
    if (rc == ERROR_SUCCESS || rc == ERROR_ALREADY_EXISTS || rc == ERROR_FILE_EXISTS) return TRUE;
    StringCchPrintfW(err, err_cch, L"无法创建安装目录：%s\r\n错误码：%d", path, rc);
    return FALSE;
}

static BOOL temp_file_path(const WCHAR *suffix, WCHAR *out, size_t cch) {
    WCHAR dir[MAX_PATH];
    if (!GetTempPathW(ARRAYSIZE(dir), dir)) return FALSE;
    return SUCCEEDED(StringCchPrintfW(out, cch, APP_INSTALL_TEMP_FILE_FORMAT, dir, (unsigned long)GetCurrentProcessId(), suffix));
}

static BOOL read_payload_trailer(FILE *self, int64_t file_size, PAYLOAD_TRAILER *trailer) {
    if (file_size < (int64_t)sizeof(*trailer)) return FALSE;
    if (_fseeki64(self, file_size - (int64_t)sizeof(*trailer), SEEK_SET) != 0) return FALSE;
    if (fread(trailer, 1, sizeof(*trailer), self) != sizeof(*trailer)) return FALSE;
    if (memcmp(trailer->magic, PAYLOAD_MAGIC, sizeof(PAYLOAD_MAGIC)) != 0) return FALSE;
    if (trailer->offset > (uint64_t)file_size || trailer->size > (uint64_t)file_size) return FALSE;
    if (trailer->offset > UINT64_MAX - trailer->size ||
        trailer->offset + trailer->size > UINT64_MAX - sizeof(*trailer)) return FALSE;
    if (trailer->offset + trailer->size + sizeof(*trailer) != (uint64_t)file_size) return FALSE;
    return TRUE;
}

static BOOL extract_embedded_zip(const WCHAR *zip_path, WCHAR *err, size_t err_cch) {
    WCHAR exe[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exe, ARRAYSIZE(exe))) {
        StringCchCopyW(err, err_cch, L"无法定位安装器自身路径。");
        return FALSE;
    }
    FILE *self = _wfopen(exe, L"rb");
    if (!self) {
        StringCchCopyW(err, err_cch, L"无法读取安装器文件。");
        return FALSE;
    }
    _fseeki64(self, 0, SEEK_END);
    int64_t file_size = _ftelli64(self);
    PAYLOAD_TRAILER trailer;
    if (!read_payload_trailer(self, file_size, &trailer)) {
        fclose(self);
        StringCchCopyW(err, err_cch, L"这个安装器没有内嵌 portable 包，请重新运行 package-installer-mingw.bat。");
        return FALSE;
    }

    FILE *zip = _wfopen(zip_path, L"wb");
    if (!zip) {
        fclose(self);
        StringCchCopyW(err, err_cch, L"无法创建临时压缩包。");
        return FALSE;
    }

    if (_fseeki64(self, (int64_t)trailer.offset, SEEK_SET) != 0) {
        fclose(zip);
        fclose(self);
        StringCchCopyW(err, err_cch, L"读取内嵌 portable 包失败。");
        return FALSE;
    }

    BYTE *copy_buffer = (BYTE *)xalloc(APP_INSTALL_COPY_BUFFER_BYTES);
    if (!copy_buffer) {
        fclose(zip);
        fclose(self);
        StringCchCopyW(err, err_cch, L"内存不足。");
        return FALSE;
    }

    uint64_t left = trailer.size;
    uint64_t bytes_copied = 0;
    while (left > 0) {
        size_t chunk = left > APP_INSTALL_COPY_BUFFER_BYTES ? APP_INSTALL_COPY_BUFFER_BYTES : (size_t)left;
        size_t bytes_read = fread(copy_buffer, 1, chunk, self);
        if (bytes_read != chunk || fwrite(copy_buffer, 1, chunk, zip) != chunk) {
            xfree(copy_buffer);
            fclose(zip);
            fclose(self);
            StringCchCopyW(err, err_cch, L"写出临时压缩包失败。");
            return FALSE;
        }
        left -= chunk;
        bytes_copied += chunk;
        if (trailer.size > 0) {
            int pos = 5 + (int)((bytes_copied * 25) / trailer.size);
            post_status(pos, L"正在准备内嵌 portable 包...");
        }
    }

    xfree(copy_buffer);
    fclose(zip);
    fclose(self);
    return TRUE;
}

static WCHAR *ps_single_quote(const WCHAR *path) {
    size_t extra = 0;
    for (const WCHAR *p = path; p && *p; ++p) {
        if (*p == L'\'') extra++;
    }
    size_t len = wcslen(path ? path : L"");
    if (len > SIZE_MAX - extra - 3) return NULL;
    WCHAR *out = (WCHAR *)xalloc((len + extra + 3) * sizeof(WCHAR));
    if (!out) return NULL;
    WCHAR *w = out;
    *w++ = L'\'';
    for (const WCHAR *p = path ? path : L""; *p; ++p) {
        *w++ = *p;
        if (*p == L'\'') *w++ = L'\'';
    }
    *w++ = L'\'';
    *w = L'\0';
    return out;
}

static BOOL write_expand_script(const WCHAR *script_path, const WCHAR *zip_path, const WCHAR *target, WCHAR *err, size_t err_cch) {
    WCHAR *zip_q = ps_single_quote(zip_path);
    WCHAR *target_q = ps_single_quote(target);
    if (!zip_q || !target_q) {
        xfree(zip_q);
        xfree(target_q);
        StringCchCopyW(err, err_cch, L"内存不足。");
        return FALSE;
    }
    WCHAR content[4096];
    HRESULT hr = StringCchPrintfW(
        content,
        ARRAYSIZE(content),
        L"$ErrorActionPreference = 'Stop'\r\n"
        L"Expand-Archive -LiteralPath %s -DestinationPath %s -Force\r\n",
        zip_q,
        target_q
    );
    xfree(zip_q);
    xfree(target_q);
    if (FAILED(hr)) {
        StringCchCopyW(err, err_cch, L"安装路径太长。");
        return FALSE;
    }
    HANDLE h = CreateFileW(script_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        StringCchCopyW(err, err_cch, L"无法创建临时解压脚本。");
        return FALSE;
    }
    WORD bom = 0xFEFF;
    DWORD written = 0;
    DWORD content_bytes = (DWORD)(wcslen(content) * sizeof(WCHAR));
    BOOL write_succeeded = WriteFile(h, &bom, sizeof(bom), &written, NULL) && written == sizeof(bom) &&
                           WriteFile(h, content, content_bytes, &written, NULL) && written == content_bytes;
    CloseHandle(h);
    if (!write_succeeded) StringCchCopyW(err, err_cch, L"写入临时解压脚本失败。");
    return write_succeeded;
}

static BOOL write_model_download_script(const WCHAR *script_path, const WCHAR *target,
                                        const APP_INSTALL_MODEL_OPTION *model,
                                        const APP_INSTALL_QUANT_OPTION *quant,
                                        WCHAR *err, size_t err_cch) {
    WCHAR *target_q = ps_single_quote(target);
    WCHAR *repo_q = ps_single_quote(model ? model->repo : L"");
    WCHAR *prefix_q = ps_single_quote(model ? model->file_prefix : L"");
    WCHAR *quant_q = ps_single_quote(quant ? quant->suffix : L"");
    if (!target_q || !repo_q || !prefix_q || !quant_q) {
        xfree(target_q);
        xfree(repo_q);
        xfree(prefix_q);
        xfree(quant_q);
        StringCchCopyW(err, err_cch, L"内存不足。");
        return FALSE;
    }
    WCHAR content[16384];
    HRESULT hr = StringCchPrintfW(
        content,
        ARRAYSIZE(content),
        L"$ErrorActionPreference = 'Stop'\r\n"
        L"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\r\n"
        L"$target = %s\r\n"
        L"$repo = %s\r\n"
        L"$filePrefix = %s\r\n"
        L"$quant = %s\r\n"
        L"$modelsDir = Join-Path $target '%s'\r\n"
        L"$treeUrl = \"https://huggingface.co/api/models/$repo/tree/main?recursive=1\"\r\n"
        L"$downloadBase = \"https://huggingface.co/$repo/resolve/main\"\r\n"
        L"$baseName = \"$filePrefix-$quant\"\r\n"
        L"New-Item -ItemType Directory -Force -Path $modelsDir | Out-Null\r\n"
        L"$tree = Invoke-RestMethod -Uri $treeUrl -UseBasicParsing\r\n"
        L"$files = @($tree | Where-Object {\r\n"
        L"  $leaf = ([string]$_.path) -replace '^.*/',''\r\n"
        L"  $_.type -eq 'file' -and ($leaf -eq \"$baseName.gguf\" -or $leaf -like \"$baseName-*-of-*.gguf\")\r\n"
        L"} | Sort-Object path)\r\n"
        L"if ($files.Count -eq 0) { throw \"Selected model file not found: $repo / $baseName\" }\r\n"
        L"$modelConfigName = (([string]$files[0].path) -replace '^.*/','')\r\n"
        L"foreach ($file in $files) {\r\n"
        L"  $remotePath = [string]$file.path\r\n"
        L"  $fileName = $remotePath -replace '^.*/',''\r\n"
        L"  if ($fileName -match '[\\\\/:]') { throw \"Unsafe model file name: $fileName\" }\r\n"
        L"  $modelPath = Join-Path $modelsDir $fileName\r\n"
        L"  $tmpPath = $modelPath + '.download'\r\n"
        L"  $expected = $null\r\n"
        L"  if ($file.lfs -and $file.lfs.oid) { $expected = ([string]$file.lfs.oid).ToLowerInvariant() }\r\n"
        L"  if (-not $expected) { throw \"No SHA256 metadata for model file: $remotePath\" }\r\n"
        L"  if (Test-Path -LiteralPath $modelPath) {\r\n"
        L"    $existing = (Get-FileHash -Algorithm SHA256 -LiteralPath $modelPath).Hash.ToLowerInvariant()\r\n"
        L"    if ($existing -eq $expected) { continue }\r\n"
        L"    Remove-Item -LiteralPath $modelPath -Force\r\n"
        L"  }\r\n"
        L"  if (Test-Path -LiteralPath $tmpPath) { Remove-Item -LiteralPath $tmpPath -Force }\r\n"
        L"  $url = \"$downloadBase/$remotePath?download=true\"\r\n"
        L"  if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {\r\n"
        L"    Start-BitsTransfer -Source $url -Destination $tmpPath\r\n"
        L"  } else {\r\n"
        L"    Invoke-WebRequest -Uri $url -OutFile $tmpPath -UseBasicParsing\r\n"
        L"  }\r\n"
        L"  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $tmpPath).Hash.ToLowerInvariant()\r\n"
        L"  if ($actual -ne $expected) {\r\n"
        L"    Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue\r\n"
        L"    throw \"Model SHA256 mismatch. Expected $expected but got $actual\"\r\n"
        L"  }\r\n"
        L"  Move-Item -LiteralPath $tmpPath -Destination $modelPath -Force\r\n"
        L"}\r\n"
        L"$configPath = Join-Path $target 'tools\\payload_watermark\\worker_config.txt'\r\n"
        L"if (Test-Path -LiteralPath $configPath) {\r\n"
        L"  $lines = @(Get-Content -LiteralPath $configPath -Encoding UTF8)\r\n"
        L"  $seen = $false\r\n"
        L"  $updated = @()\r\n"
        L"  foreach ($line in $lines) {\r\n"
        L"    if ($line -match '^\\s*model\\s*=') { $updated += \"model=$modelConfigName\"; $seen = $true } else { $updated += $line }\r\n"
        L"  }\r\n"
        L"  if (-not $seen) { $updated = @(\"model=$modelConfigName\") + $updated }\r\n"
        L"  Set-Content -LiteralPath $configPath -Value $updated -Encoding UTF8\r\n"
        L"}\r\n",
        target_q,
        repo_q,
        prefix_q,
        quant_q,
        APP_INSTALL_MODELS_DIR_NAME
    );
    xfree(target_q);
    xfree(repo_q);
    xfree(prefix_q);
    xfree(quant_q);
    if (FAILED(hr)) {
        StringCchCopyW(err, err_cch, L"模型下载脚本太长。");
        return FALSE;
    }
    HANDLE h = CreateFileW(script_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        StringCchCopyW(err, err_cch, L"无法创建模型下载脚本。");
        return FALSE;
    }
    WORD bom = 0xFEFF;
    DWORD written = 0;
    DWORD content_bytes = (DWORD)(wcslen(content) * sizeof(WCHAR));
    BOOL write_succeeded = WriteFile(h, &bom, sizeof(bom), &written, NULL) && written == sizeof(bom) &&
                           WriteFile(h, content, content_bytes, &written, NULL) && written == content_bytes;
    CloseHandle(h);
    if (!write_succeeded) StringCchCopyW(err, err_cch, L"写入模型下载脚本失败。");
    return write_succeeded;
}

static BOOL run_powershell_script(const WCHAR *script_path, WCHAR *err, size_t err_cch) {
    WCHAR cmd[MAX_PATH * 2];
    if (FAILED(StringCchPrintfW(
            cmd,
            ARRAYSIZE(cmd),
            L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%s\"",
            script_path))) {
        StringCchCopyW(err, err_cch, L"PowerShell 命令太长。");
        return FALSE;
    }
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    WCHAR mutable_cmd[MAX_PATH * 2];
    StringCchCopyW(mutable_cmd, ARRAYSIZE(mutable_cmd), cmd);
    BOOL started = CreateProcessW(NULL, mutable_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!started) {
        StringCchPrintfW(err, err_cch, L"无法启动 powershell.exe，错误码：%lu", (unsigned long)GetLastError());
        return FALSE;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (exit_code != 0) {
        StringCchPrintfW(err, err_cch, L"PowerShell 脚本失败，返回码：%lu", (unsigned long)exit_code);
        return FALSE;
    }
    return TRUE;
}

static DWORD WINAPI install_thread_proc(LPVOID param) {
    INSTALL_CTX *ctx = (INSTALL_CTX *)param;
    const APP_INSTALL_MODEL_OPTION *model = install_model_option(ctx->model_index);
    const APP_INSTALL_QUANT_OPTION *quant = install_quant_option(ctx->quant_index);
    WCHAR err[512] = L"";
    WCHAR zip_path[MAX_PATH] = L"";
    WCHAR ps1_path[MAX_PATH] = L"";
    WCHAR exe_path[MAX_PATH] = L"";
    WCHAR models_path[MAX_PATH] = L"";

    post_status(3, L"正在创建安装目录...");
    if (!ensure_directory(ctx->target, err, ARRAYSIZE(err))) goto fail;
    if (!temp_file_path(L".zip", zip_path, ARRAYSIZE(zip_path)) ||
        !temp_file_path(L".ps1", ps1_path, ARRAYSIZE(ps1_path))) {
        StringCchCopyW(err, ARRAYSIZE(err), L"无法创建临时路径。");
        goto fail;
    }

    post_status(5, L"正在读取安装器内嵌 portable 包...");
    if (!extract_embedded_zip(zip_path, err, ARRAYSIZE(err))) goto fail;

    post_status(35, L"正在解压 portable 应用...");
    if (!write_expand_script(ps1_path, zip_path, ctx->target, err, ARRAYSIZE(err))) goto fail;
    if (!run_powershell_script(ps1_path, err, ARRAYSIZE(err))) goto fail;

    post_status(70, L"正在下载所选 Qwen3 模型，首次安装需要较长时间...");
    if (!write_model_download_script(ps1_path, ctx->target, model, quant, err, ARRAYSIZE(err))) goto fail;
    if (!run_powershell_script(ps1_path, err, ARRAYSIZE(err))) goto fail;

    if (!join_path(exe_path, ARRAYSIZE(exe_path), ctx->target, APP_INSTALL_EXE_NAME) ||
        GetFileAttributesW(exe_path) == INVALID_FILE_ATTRIBUTES) {
        StringCchCopyW(err, ARRAYSIZE(err), L"安装完成校验失败：没有找到 ChineseInputAgent.exe。");
        goto fail;
    }
    if (!join_path(models_path, ARRAYSIZE(models_path), ctx->target, APP_INSTALL_MODELS_DIR_NAME) ||
        !directory_has_gguf(models_path)) {
        StringCchCopyW(err, ARRAYSIZE(err), L"安装完成校验失败：没有找到已下载的 GGUF 模型。");
        goto fail;
    }

    DeleteFileW(zip_path);
    DeleteFileW(ps1_path);
    post_status(100, L"安装完成。");
    post_done(TRUE, exe_path);
    xfree(ctx);
    return 0;

fail:
    DeleteFileW(zip_path);
    DeleteFileW(ps1_path);
    post_done(FALSE, err[0] ? err : L"安装失败。");
    xfree(ctx);
    return 1;
}

static void browse_for_folder(HWND hwnd) {
    BROWSEINFOW bi;
    ZeroMemory(&bi, sizeof(bi));
    bi.hwndOwner = hwnd;
    bi.lpszTitle = L"选择安装路径";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_USENEWUI;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return;
    WCHAR path[MAX_PATH];
    if (SHGetPathFromIDListW(pidl, path)) {
        WCHAR final_path[MAX_PATH];
        if (join_path(final_path, ARRAYSIZE(final_path), path, APP_INSTALL_SUBDIR_NAME)) {
            SetWindowTextW(g_path_edit, final_path);
        }
    }
    CoTaskMemFree(pidl);
}

static void start_install(HWND hwnd) {
    WCHAR target[MAX_PATH];
    GetWindowTextW(g_path_edit, target, ARRAYSIZE(target));
    if (!target[0]) {
        MessageBoxW(hwnd, L"请选择安装路径。", CIA_INSTALLER_TITLE, MB_ICONERROR | MB_OK);
        return;
    }
    INSTALL_CTX *ctx = (INSTALL_CTX *)xalloc(sizeof(*ctx));
    if (!ctx) {
        MessageBoxW(hwnd, L"内存不足。", CIA_INSTALLER_TITLE, MB_ICONERROR | MB_OK);
        return;
    }
    StringCchCopyW(ctx->target, ARRAYSIZE(ctx->target), target);
    ctx->launch_after = Button_GetCheck(g_launch_check) == BST_CHECKED;
    ctx->model_index = (int)SendMessageW(g_model_combo, CB_GETCURSEL, 0, 0);
    ctx->quant_index = (int)SendMessageW(g_quant_combo, CB_GETCURSEL, 0, 0);
    set_install_controls_enabled(FALSE);
    SendMessageW(g_progress, PBM_SETPOS, 0, 0);
    SetWindowTextW(g_status, L"准备安装...");
    HANDLE thread = CreateThread(NULL, 0, install_thread_proc, ctx, 0, NULL);
    if (!thread) {
        xfree(ctx);
        set_install_controls_enabled(TRUE);
        MessageBoxW(hwnd, L"无法启动安装线程。", CIA_INSTALLER_TITLE, MB_ICONERROR | MB_OK);
        return;
    }
    CloseHandle(thread);
}

static void layout(HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);
    int w = rc.right - rc.left;
    int margin = 16;
    int label_h = 22;
    int edit_h = 30;
    int button_h = 34;
    int browse_w = 84;
    int y = margin;
    MoveWindow(GetDlgItem(hwnd, IDC_INSTALLER_PATH_LABEL), margin, y, w - margin * 2, label_h, TRUE);
    y += label_h + 4;
    MoveWindow(g_path_edit, margin, y, w - margin * 2 - browse_w - 8, edit_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_INSTALLER_BROWSE), w - margin - browse_w, y, browse_w, edit_h, TRUE);
    y += edit_h + 12;
    MoveWindow(GetDlgItem(hwnd, IDC_INSTALLER_MODEL_LABEL), margin, y, w - margin * 2, label_h, TRUE);
    y += label_h + 4;
    MoveWindow(g_model_combo, margin, y, w - margin * 2, edit_h + 180, TRUE);
    y += edit_h + 12;
    MoveWindow(GetDlgItem(hwnd, IDC_INSTALLER_QUANT_LABEL), margin, y, w - margin * 2, label_h, TRUE);
    y += label_h + 4;
    MoveWindow(g_quant_combo, margin, y, w - margin * 2, edit_h + 120, TRUE);
    y += edit_h + 12;
    MoveWindow(g_launch_check, margin, y, w - margin * 2, 24, TRUE);
    y += 32;
    MoveWindow(g_progress, margin, y, w - margin * 2, 20, TRUE);
    y += 28;
    MoveWindow(g_status, margin, y, w - margin * 2, 44, TRUE);
    MoveWindow(g_install_button, w - margin - 190, rc.bottom - margin - button_h, 88, button_h, TRUE);
    MoveWindow(g_close_button, w - margin - 94, rc.bottom - margin - button_h, 94, button_h, TRUE);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
    case WM_CREATE: {
        HWND label = CreateWindowExW(0, L"STATIC", L"安装路径", WS_CHILD | WS_VISIBLE,
                                     0, 0, 0, 0, hwnd, (HMENU)IDC_INSTALLER_PATH_LABEL, g_instance, NULL);
        g_path_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                      0, 0, 0, 0, hwnd, (HMENU)IDC_INSTALLER_PATH_EDIT, g_instance, NULL);
        HWND browse = CreateWindowExW(0, L"BUTTON", L"浏览...", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                      0, 0, 0, 0, hwnd, (HMENU)IDC_INSTALLER_BROWSE, g_instance, NULL);
        HWND model_label = CreateWindowExW(0, L"STATIC", L"模型", WS_CHILD | WS_VISIBLE,
                                           0, 0, 0, 0, hwnd, (HMENU)IDC_INSTALLER_MODEL_LABEL, g_instance, NULL);
        g_model_combo = CreateWindowExW(0, WC_COMBOBOXW, L"",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                        0, 0, 0, 0, hwnd, (HMENU)IDC_INSTALLER_MODEL_COMBO, g_instance, NULL);
        HWND quant_label = CreateWindowExW(0, L"STATIC", L"量化精度", WS_CHILD | WS_VISIBLE,
                                           0, 0, 0, 0, hwnd, (HMENU)IDC_INSTALLER_QUANT_LABEL, g_instance, NULL);
        g_quant_combo = CreateWindowExW(0, WC_COMBOBOXW, L"",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                        0, 0, 0, 0, hwnd, (HMENU)IDC_INSTALLER_QUANT_COMBO, g_instance, NULL);
        g_launch_check = CreateWindowExW(0, L"BUTTON", L"安装完成后启动 ChineseInputAgent",
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                         0, 0, 0, 0, hwnd, (HMENU)IDC_INSTALLER_LAUNCH, g_instance, NULL);
        g_progress = CreateWindowExW(0, PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE,
                                     0, 0, 0, 0, hwnd, (HMENU)IDC_INSTALLER_PROGRESS, g_instance, NULL);
        g_status = CreateWindowExW(0, L"STATIC", L"选择路径后点击安装。", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                   0, 0, 0, 0, hwnd, (HMENU)IDC_INSTALLER_STATUS, g_instance, NULL);
        g_install_button = CreateWindowExW(0, L"BUTTON", L"安装", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                           0, 0, 0, 0, hwnd, (HMENU)IDC_INSTALLER_INSTALL, g_instance, NULL);
        g_close_button = CreateWindowExW(0, L"BUTTON", L"关闭", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                         0, 0, 0, 0, hwnd, (HMENU)IDC_INSTALLER_CLOSE, g_instance, NULL);
        HWND controls[] = {label, g_path_edit, browse, model_label, g_model_combo, quant_label, g_quant_combo,
                           g_launch_check, g_progress, g_status, g_install_button, g_close_button};
        for (size_t i = 0; i < ARRAYSIZE(controls); ++i) set_font(controls[i]);
        populate_install_option_combos();
        WCHAR path[MAX_PATH];
        default_install_path(path, ARRAYSIZE(path));
        SetWindowTextW(g_path_edit, path);
        Button_SetCheck(g_launch_check, BST_CHECKED);
        SendMessageW(g_progress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        layout(hwnd);
        break;
    }
    case WM_SIZE:
        layout(hwnd);
        break;
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case IDC_INSTALLER_BROWSE:
            browse_for_folder(hwnd);
            break;
        case IDC_INSTALLER_INSTALL:
            start_install(hwnd);
            break;
        case IDC_INSTALLER_CLOSE:
            DestroyWindow(hwnd);
            break;
        }
        break;
    case WM_APP_INSTALL_STATUS: {
        WCHAR *text = (WCHAR *)lparam;
        SendMessageW(g_progress, PBM_SETPOS, wparam, 0);
        SetWindowTextW(g_status, text ? text : L"");
        xfree(text);
        break;
    }
    case WM_APP_INSTALL_DONE: {
        WCHAR *text = (WCHAR *)lparam;
        BOOL install_succeeded = (BOOL)wparam;
        set_install_controls_enabled(TRUE);
        if (install_succeeded) {
            SetWindowTextW(g_status, L"安装完成。");
            SendMessageW(g_progress, PBM_SETPOS, 100, 0);
            if (Button_GetCheck(g_launch_check) == BST_CHECKED && text && text[0]) {
                ShellExecuteW(hwnd, L"open", text, NULL, NULL, SW_SHOWNORMAL);
            }
        } else {
            SetWindowTextW(g_status, text ? text : L"安装失败。");
            MessageBoxW(hwnd, text ? text : L"安装失败。", CIA_INSTALLER_TITLE, MB_ICONERROR | MB_OK);
        }
        xfree(text);
        break;
    }
    case WM_CLOSE:
        DestroyWindow(hwnd);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE prev, PWSTR cmd, int show) {
    (void)prev;
    (void)cmd;
    g_instance = instance;
    OleInitialize(NULL);
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    g_font = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                         OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                         DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

    WNDCLASSW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = INSTALLER_WINDOW_CLASS_NAME;
    if (!RegisterClassW(&wc)) return 1;

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, CIA_INSTALLER_TITLE,
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_SIZEBOX,
                                CW_USEDEFAULT, CW_USEDEFAULT, 620, 390,
                                NULL, NULL, instance, NULL);
    if (!hwnd) return 1;
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (g_font) DeleteObject(g_font);
    OleUninitialize();
    return 0;
}
