#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _CRT_SECURE_NO_WARNINGS

#include "app_llm.h"
#include "app_shared.h"

typedef struct LOCAL_LLM_WORKER {
    CRITICAL_SECTION lock;
    BOOL lock_ready;
    BOOL process_ready;
    PROCESS_INFORMATION process;
    HANDLE stdin_write;
    HANDLE stdout_read;
    WCHAR stderr_path[MAX_PATH];
    DWORD next_id;
} LOCAL_LLM_WORKER;

static LOCAL_LLM_WORKER g_llm_worker;
static HANDLE g_llm_worker_job;
static APP_LLM_CANCEL_FN g_cancel_fn;
static APP_LLM_PROGRESS_FN g_progress_fn;

static WCHAR *llm_dup_wide(const WCHAR *s) {
    size_t n = wcslen(s);
    WCHAR *p = (WCHAR *)xalloc((n + 1) * sizeof(WCHAR));
    if (!p) return NULL;
    CopyMemory(p, s, (n + 1) * sizeof(WCHAR));
    return p;
}

static BOOL app_llm_cancelled(void) {
    return g_cancel_fn ? g_cancel_fn() : FALSE;
}

void app_llm_init(APP_LLM_CANCEL_FN cancel_fn, APP_LLM_PROGRESS_FN progress_fn) {
    ZeroMemory(&g_llm_worker, sizeof(g_llm_worker));
    g_cancel_fn = cancel_fn;
    g_progress_fn = progress_fn;
    InitializeCriticalSection(&g_llm_worker.lock);
    g_llm_worker.lock_ready = TRUE;
}

void app_llm_cleanup(void) {
    shutdown_local_llm_worker();
    close_local_llm_job();
    if (g_llm_worker.lock_ready) {
        DeleteCriticalSection(&g_llm_worker.lock);
        g_llm_worker.lock_ready = FALSE;
    }
}

static BOOL read_line_handle_cancelable(HANDLE h, HANDLE process, STRB *line, BOOL *cancelled) {
    ZeroMemory(line, sizeof(*line));
    if (cancelled) *cancelled = FALSE;
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(h, NULL, 0, NULL, &available, NULL)) {
            return line->len > 0;
        }
        if (available == 0) {
            if (process && WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
                return line->len > 0;
            }
            if (app_llm_cancelled()) {
                if (cancelled) *cancelled = TRUE;
                return FALSE;
            }
            Sleep(50);
            continue;
        }
        char ch = 0;
        DWORD read = 0;
        if (!ReadFile(h, &ch, 1, &read, NULL) || read != 1) {
            return line->len > 0;
        }
        if (ch == '\n') return TRUE;
        if (ch == '\r') continue;
        if (line->len > 1024 * 1024) return FALSE;
        if (!strb_append_n(line, &ch, 1)) return FALSE;
    }
}

static BOOL append_json_wide_field(STRB *b, const char *name, const WCHAR *value, BOOL comma) {
    if (comma && !strb_append(b, ",")) return FALSE;
    return strb_append(b, "\"") &&
           strb_append(b, name) &&
           strb_append(b, "\":\"") &&
           append_json_escaped_wide(b, value ? value : L"") &&
           strb_append(b, "\"");
}

static BOOL build_worker_request_json(STRB *b, DWORD id, const char *cmd,
                                      const WCHAR *payload_path, const WCHAR *text_path,
                                      const WCHAR *topic_path, const WCHAR *seed,
                                      const WCHAR *out_path, int tail_tokens) {
    ZeroMemory(b, sizeof(*b));
    if (!strb_appendf(b, "{\"id\":%lu,\"cmd\":\"%s\"", (unsigned long)id, cmd)) return FALSE;
    if (payload_path && !append_json_wide_field(b, "payload", payload_path, TRUE)) return FALSE;
    if (text_path && !append_json_wide_field(b, "text", text_path, TRUE)) return FALSE;
    if (topic_path && !append_json_wide_field(b, "topic_file", topic_path, TRUE)) return FALSE;
    if (seed && !append_json_wide_field(b, "seed", seed, TRUE)) return FALSE;
    if (out_path && !append_json_wide_field(b, "out", out_path, TRUE)) return FALSE;
    if (tail_tokens >= 0 && !strb_appendf(b, ",\"tail_tokens\":%d", tail_tokens)) return FALSE;
    return strb_append(b, "}\n");
}

static BOOL response_json_ok(const char *line) {
    return line && (strstr(line, "\"ok\": true") || strstr(line, "\"ok\":true"));
}

static BOOL json_line_has_string(const char *line, const char *name, const char *value) {
    if (!line || !name || !value) return FALSE;
    char pattern[96];
    sprintf(pattern, "\"%s\":\"%s\"", name, value);
    return strstr(line, pattern) != NULL;
}

static BOOL json_get_size_t_field(const char *line, const char *name, size_t *out) {
    if (!line || !name || !out) return FALSE;
    char pattern[64];
    sprintf(pattern, "\"%s\":", name);
    const char *p = strstr(line, pattern);
    if (!p) return FALSE;
    p += strlen(pattern);
    while (*p == ' ' || *p == '\t') ++p;
    size_t value = 0;
    BOOL any = FALSE;
    while (*p >= '0' && *p <= '9') {
        any = TRUE;
        value = value * 10 + (size_t)(*p - '0');
        ++p;
    }
    if (!any) return FALSE;
    *out = value;
    return TRUE;
}

static BOOL json_get_double_field(const char *line, const char *name, double *out) {
    if (!line || !name || !out) return FALSE;
    char pattern[64];
    sprintf(pattern, "\"%s\":", name);
    const char *p = strstr(line, pattern);
    if (!p) return FALSE;
    p += strlen(pattern);
    while (*p == ' ' || *p == '\t') ++p;
    char *end = NULL;
    double value = strtod(p, &end);
    if (end == p) return FALSE;
    *out = value;
    return TRUE;
}

static int hex_value(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static BOOL strb_append_utf8_codepoint(STRB *b, unsigned cp) {
    char tmp[4];
    size_t n = 0;
    if (cp <= 0x7f) {
        tmp[n++] = (char)cp;
    } else if (cp <= 0x7ff) {
        tmp[n++] = (char)(0xc0 | (cp >> 6));
        tmp[n++] = (char)(0x80 | (cp & 0x3f));
    } else {
        tmp[n++] = (char)(0xe0 | (cp >> 12));
        tmp[n++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        tmp[n++] = (char)(0x80 | (cp & 0x3f));
    }
    return strb_append_n(b, tmp, n);
}

static BOOL json_get_wide_string_field(const char *line, const char *name, WCHAR **out) {
    *out = NULL;
    if (!line || !name) return FALSE;
    char pattern[96];
    sprintf(pattern, "\"%s\":\"", name);
    const char *p = strstr(line, pattern);
    if (!p) return FALSE;
    p += strlen(pattern);
    STRB utf8 = {0};
    BOOL ok = TRUE;
    while (*p && *p != '"') {
        if (*p == '\\') {
            ++p;
            if (!*p) { ok = FALSE; break; }
            switch (*p) {
            case '"': ok = strb_append_n(&utf8, "\"", 1); break;
            case '\\': ok = strb_append_n(&utf8, "\\", 1); break;
            case '/': ok = strb_append_n(&utf8, "/", 1); break;
            case 'b': ok = strb_append_n(&utf8, "\b", 1); break;
            case 'f': ok = strb_append_n(&utf8, "\f", 1); break;
            case 'n': ok = strb_append_n(&utf8, "\n", 1); break;
            case 'r': ok = strb_append_n(&utf8, "\r", 1); break;
            case 't': ok = strb_append_n(&utf8, "\t", 1); break;
            case 'u': {
                unsigned cp = 0;
                for (int i = 0; i < 4; ++i) {
                    int h = hex_value(p[1 + i]);
                    if (h < 0) { ok = FALSE; break; }
                    cp = (cp << 4) | (unsigned)h;
                }
                if (ok) {
                    ok = strb_append_utf8_codepoint(&utf8, cp);
                    p += 4;
                }
                break;
            }
            default:
                ok = FALSE;
                break;
            }
            if (!ok) break;
            ++p;
            continue;
        }
        ok = strb_append_n(&utf8, p, 1);
        if (!ok) break;
        ++p;
    }
    if (ok && *p != '"') ok = FALSE;
    if (ok) {
        if (utf8.len == 0) {
            *out = llm_dup_wide(L"");
            ok = *out != NULL;
        } else {
            ok = utf8_to_wide_n(utf8.data, (int)utf8.len, out);
        }
    }
    strb_free(&utf8);
    return ok;
}

static BOOL ensure_local_llm_job(void) {
    if (g_llm_worker_job) return TRUE;
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (!job) return FALSE;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
    ZeroMemory(&info, sizeof(info));
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info))) {
        CloseHandle(job);
        return FALSE;
    }
    g_llm_worker_job = job;
    return TRUE;
}

void close_local_llm_job(void) {
    if (g_llm_worker_job) {
        CloseHandle(g_llm_worker_job);
        g_llm_worker_job = NULL;
    }
}

static void close_local_llm_worker_locked(BOOL terminate) {
    if (g_llm_worker.process.hProcess) {
        if (terminate) {
            TerminateProcess(g_llm_worker.process.hProcess, 1);
            WaitForSingleObject(g_llm_worker.process.hProcess, 2000);
        }
        CloseHandle(g_llm_worker.process.hProcess);
    }
    if (g_llm_worker.process.hThread) CloseHandle(g_llm_worker.process.hThread);
    if (g_llm_worker.stdin_write) CloseHandle(g_llm_worker.stdin_write);
    if (g_llm_worker.stdout_read) CloseHandle(g_llm_worker.stdout_read);
    ZeroMemory(&g_llm_worker.process, sizeof(g_llm_worker.process));
    g_llm_worker.stdin_write = NULL;
    g_llm_worker.stdout_read = NULL;
    g_llm_worker.process_ready = FALSE;
}

static BOOL local_llm_worker_alive_locked(void) {
    if (!g_llm_worker.process_ready || !g_llm_worker.process.hProcess) return FALSE;
    DWORD code = 0;
    return GetExitCodeProcess(g_llm_worker.process.hProcess, &code) && code == STILL_ACTIVE;
}

static BOOL start_local_llm_worker_locked(WCHAR *err, size_t err_cch) {
    if (local_llm_worker_alive_locked()) return TRUE;
    close_local_llm_worker_locked(FALSE);

    WCHAR script[MAX_PATH], workdir[MAX_PATH], python[MAX_PATH];
    if (!find_local_worker(script, ARRAYSIZE(script), workdir, ARRAYSIZE(workdir),
                           python, ARRAYSIZE(python), err, err_cch)) {
        return FALSE;
    }

    HANDLE stdin_read = NULL, stdin_write = NULL, stdout_read = NULL, stdout_write = NULL;
    HANDLE stderr_file = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&stdin_read, &stdin_write, &sa, 0) ||
        !CreatePipe(&stdout_read, &stdout_write, &sa, 0)) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }
    SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);

    if (!make_temp_path(g_llm_worker.stderr_path, ARRAYSIZE(g_llm_worker.stderr_path))) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }
    stderr_file = CreateFileW(g_llm_worker.stderr_path, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NORMAL, NULL);
    if (stderr_file == INVALID_HANDLE_VALUE) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }

    WSTRB cmd = {0};
    if (python[0]) {
        if (!append_quoted_arg(&cmd, python) ||
            !wstrb_append(&cmd, L" -X utf8 ") ||
            !append_quoted_arg(&cmd, script)) {
            wstrb_free(&cmd);
            set_error(err, err_cch, L"Carrier text assembly failed.");
            goto fail;
        }
    } else {
        if (!append_quoted_arg(&cmd, script)) {
            wstrb_free(&cmd);
            set_error(err, err_cch, L"Carrier text assembly failed.");
            goto fail;
        }
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = stdin_read;
    si.hStdOutput = stdout_write;
    si.hStdError = stderr_file;

    WCHAR *mutable_cmd = llm_dup_wide(cmd.data);
    wstrb_free(&cmd);
    if (!mutable_cmd) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }
    BOOL started = CreateProcessW(NULL, mutable_cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                                  NULL, workdir, &si, &pi);
    secure_free_wide(mutable_cmd);
    if (!started) {
        set_error(err, err_cch, L"", (unsigned long)GetLastError());
        goto fail;
    }
    if (ensure_local_llm_job()) {
        AssignProcessToJobObject(g_llm_worker_job, pi.hProcess);
    }

    CloseHandle(stdin_read);
    CloseHandle(stdout_write);
    CloseHandle(stderr_file);
    stdin_read = NULL;
    stdout_write = NULL;
    stderr_file = INVALID_HANDLE_VALUE;

    g_llm_worker.process = pi;
    g_llm_worker.stdin_write = stdin_write;
    g_llm_worker.stdout_read = stdout_read;
    stdin_write = NULL;
    stdout_read = NULL;

    STRB ready = {0};
    BOOL ready_cancelled = FALSE;
    if (!read_line_handle_cancelable(g_llm_worker.stdout_read, g_llm_worker.process.hProcess, &ready, &ready_cancelled) ||
        !response_json_ok(ready.data)) {
        WCHAR *ready_w = NULL;
        if (ready_cancelled) {
            set_error(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
        } else if (ready.data && utf8_to_wide_n(ready.data, (int)ready.len, &ready_w)) {
            set_error(err, err_cch, L"Local inference worker startup failed: %s", ready_w);
            secure_free_wide(ready_w);
        } else if (!append_process_log(err, err_cch, L"Local inference worker startup failed", g_llm_worker.stderr_path)) {
            set_error(err, err_cch, L"Local inference worker startup failed and no diagnostic log was readable.");
        }
        strb_free(&ready);
        close_local_llm_worker_locked(TRUE);
        return FALSE;
    }
    strb_free(&ready);
    g_llm_worker.process_ready = TRUE;
    return TRUE;

fail:
    if (stdin_read) CloseHandle(stdin_read);
    if (stdin_write) CloseHandle(stdin_write);
    if (stdout_read) CloseHandle(stdout_read);
    if (stdout_write) CloseHandle(stdout_write);
    if (stderr_file != INVALID_HANDLE_VALUE) CloseHandle(stderr_file);
    if (g_llm_worker.stderr_path[0]) secure_delete_file(g_llm_worker.stderr_path);
    g_llm_worker.stderr_path[0] = L'\0';
    return FALSE;
}

static BOOL local_llm_worker_request(const char *cmd, const WCHAR *payload_path, const WCHAR *text_path,
                                     const WCHAR *topic_path, const WCHAR *seed, const WCHAR *out_path,
                                     int tail_tokens, HWND progress_target, WCHAR *err, size_t err_cch) {
    if (!g_llm_worker.lock_ready) {
        return FALSE;
    }
    BOOL ok = FALSE;
    EnterCriticalSection(&g_llm_worker.lock);
    if (app_llm_cancelled()) {
        set_error(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
        LeaveCriticalSection(&g_llm_worker.lock);
        return FALSE;
    }
    if (!start_local_llm_worker_locked(err, err_cch)) {
        LeaveCriticalSection(&g_llm_worker.lock);
        return FALSE;
    }
    if (app_llm_cancelled()) {
        set_error(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
        LeaveCriticalSection(&g_llm_worker.lock);
        return FALSE;
    }

    DWORD id = ++g_llm_worker.next_id;
    STRB request = {0};
    if (!build_worker_request_json(&request, id, cmd, payload_path, text_path, topic_path, seed, out_path, tail_tokens)) {
        strb_free(&request);
        set_error(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
        LeaveCriticalSection(&g_llm_worker.lock);
        return FALSE;
    }
    if (!write_all_handle(g_llm_worker.stdin_write, request.data, (DWORD)request.len)) {
        strb_free(&request);
        close_local_llm_worker_locked(TRUE);
        set_error(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
        LeaveCriticalSection(&g_llm_worker.lock);
        return FALSE;
    }
    strb_free(&request);

    for (;;) {
        STRB response = {0};
        BOOL cancelled = FALSE;
        if (!read_line_handle_cancelable(g_llm_worker.stdout_read, g_llm_worker.process.hProcess, &response, &cancelled)) {
            close_local_llm_worker_locked(TRUE);
            set_error(err, err_cch, cancelled ? L"\u5df2\u505c\u6b62\u3002" : L"\u672c\u5730 top-k worker \u672a\u8fd4\u56de\u54cd\u5e94\u3002");
            LeaveCriticalSection(&g_llm_worker.lock);
            return FALSE;
        }
        if (json_line_has_string(response.data, "type", "progress")) {
            if (progress_target && IsWindow(progress_target)) {
                size_t done = 0, total = 0;
                double tps = 0.0;
                WCHAR *partial = NULL;
                json_get_size_t_field(response.data, "done", &done);
                json_get_size_t_field(response.data, "total", &total);
                json_get_double_field(response.data, "tps", &tps);
                if (json_get_wide_string_field(response.data, "text", &partial)) {
                    if (g_progress_fn) g_progress_fn(progress_target, partial, done, total, tps);
                    secure_free_wide(partial);
                }
            }
            strb_free(&response);
            continue;
        }
        if (response_json_ok(response.data)) {
            ok = TRUE;
        } else {
            WCHAR *worker_error = NULL;
            WCHAR *response_w = NULL;
            if (json_get_wide_string_field(response.data, "error", &worker_error)) {
                set_error(err, err_cch, L"Local top-k carrier worker returned an error: %s", worker_error);
                secure_free_wide(worker_error);
            } else if (response.data && utf8_to_wide_n(response.data, (int)response.len, &response_w)) {
                set_error(err, err_cch, L"Local top-k carrier worker returned an invalid response: %s", response_w);
                secure_free_wide(response_w);
            } else {
                set_error(err, err_cch, L"Local top-k carrier worker returned an invalid response.");
            }
        }
        strb_free(&response);
        break;
    }
    LeaveCriticalSection(&g_llm_worker.lock);
    return ok;
}

static DWORD WINAPI local_llm_boot_thread_proc(LPVOID param) {
    (void)param;
    WCHAR err[512] = L"";
    if (!g_llm_worker.lock_ready) return 0;
    EnterCriticalSection(&g_llm_worker.lock);
    start_local_llm_worker_locked(err, ARRAYSIZE(err));
    LeaveCriticalSection(&g_llm_worker.lock);
    return 0;
}

void start_local_llm_background(void) {
    if (!g_llm_worker.lock_ready) return;
    HANDLE thread = CreateThread(NULL, 0, local_llm_boot_thread_proc, NULL, 0, NULL);
    if (thread) CloseHandle(thread);
}

void shutdown_local_llm_worker(void) {
    if (!g_llm_worker.lock_ready) return;
    EnterCriticalSection(&g_llm_worker.lock);
    if (local_llm_worker_alive_locked()) {
        STRB request = {0};
        if (strb_appendf(&request, "{\"id\":%lu,\"cmd\":\"shutdown\"}\n",
                        (unsigned long)(++g_llm_worker.next_id))) {
            write_all_handle(g_llm_worker.stdin_write, request.data, (DWORD)request.len);
            WaitForSingleObject(g_llm_worker.process.hProcess, 3000);
        }
        strb_free(&request);
    }
    if (local_llm_worker_alive_locked()) {
        close_local_llm_worker_locked(TRUE);
    } else {
        close_local_llm_worker_locked(FALSE);
    }
    if (g_llm_worker.stderr_path[0]) {
        secure_delete_file(g_llm_worker.stderr_path);
        g_llm_worker.stderr_path[0] = L'\0';
    }
    LeaveCriticalSection(&g_llm_worker.lock);
}

BOOL local_topk_encode_payload(const BYTE *payload, DWORD payload_len, const WCHAR *seed, const WCHAR *topic,
                                      const WCHAR *prefix, int tail_tokens, HWND progress_target,
                                      WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;

    WCHAR payload_path[MAX_PATH] = L"";
    WCHAR topic_path[MAX_PATH] = L"";
    WCHAR out_path[MAX_PATH] = L"";
    if (!make_temp_path(payload_path, ARRAYSIZE(payload_path)) ||
        !make_temp_path(topic_path, ARRAYSIZE(topic_path)) ||
        !make_temp_path(out_path, ARRAYSIZE(out_path))) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }
    if (!write_file_bytes(payload_path, payload, payload_len) ||
        !write_text_utf8_file(topic_path, topic && topic[0] ? topic : L"\u65e5\u5e38\u751f\u6d3b")) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }

    WCHAR worker_err[512] = L"";
    BOOL ran = local_llm_worker_request("encode", payload_path, NULL, topic_path, seed, out_path, tail_tokens, progress_target,
                                        worker_err, ARRAYSIZE(worker_err));
    if (!ran) {
        if (app_llm_cancelled()) {
            if (!err[0]) StringCchCopyW(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
            goto fail;
        }
        StringCchCopyW(err, err_cch, worker_err[0] ? worker_err : L"Local top-k worker returned no usable result.");
        goto fail;
    }

    WCHAR *carrier = NULL;
    if (!read_utf8_text_file(out_path, &carrier)) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }

    if (prefix && prefix[0]) {
        WSTRB b = {0};
        if (!wstrb_append(&b, prefix) || !wstrb_append(&b, carrier)) {
            secure_free_wide(carrier);
            wstrb_free(&b);
            set_error(err, err_cch, L"Carrier text assembly failed.");
            goto fail;
        }
        secure_free_wide(carrier);
        *out = b.data;
    } else {
        *out = carrier;
    }

    secure_delete_file(payload_path);
    secure_delete_file(topic_path);
    secure_delete_file(out_path);
    return TRUE;

fail:
    secure_delete_file(payload_path);
    secure_delete_file(topic_path);
    secure_delete_file(out_path);
    return FALSE;
}

BOOL local_topk_decode_payload(const WCHAR *carrier, const WCHAR *seed, BYTE **out, DWORD *out_len,
                                     WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;

    WCHAR text_path[MAX_PATH] = L"";
    WCHAR out_path[MAX_PATH] = L"";
    if (!make_temp_path(text_path, ARRAYSIZE(text_path)) ||
        !make_temp_path(out_path, ARRAYSIZE(out_path))) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }
    if (!write_text_utf8_file(text_path, carrier ? carrier : L"")) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }

    WCHAR worker_err[512] = L"";
    BOOL ran = local_llm_worker_request("decode", NULL, text_path, NULL, seed, out_path, -1, NULL,
                                        worker_err, ARRAYSIZE(worker_err));
    if (!ran) {
        if (app_llm_cancelled()) {
            if (!err[0]) StringCchCopyW(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
            goto fail;
        }
        StringCchCopyW(err, err_cch, worker_err[0] ? worker_err : L"Local top-k worker returned no usable result.");
        goto fail;
    }

    BYTE *payload = NULL;
    DWORD payload_len = 0;
    if (!read_file_bytes(out_path, &payload, &payload_len)) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }

    *out = payload;
    *out_len = payload_len;
    secure_delete_file(text_path);
    secure_delete_file(out_path);
    return TRUE;

fail:
    secure_delete_file(text_path);
    secure_delete_file(out_path);
    return FALSE;
}
