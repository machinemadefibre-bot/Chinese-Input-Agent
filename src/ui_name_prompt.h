#ifndef CHINESE_INPUT_AGENT_UI_NAME_PROMPT_H
#define CHINESE_INPUT_AGENT_UI_NAME_PROMPT_H

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stddef.h>

typedef struct UI_NAME_PROMPT_HOST {
    void (*on_close)(void *user);
    void *user;
} UI_NAME_PROMPT_HOST;

BOOL ui_prompt_key_name(HINSTANCE instance, HWND owner, HFONT ui_font,
                        const UI_NAME_PROMPT_HOST *host, WCHAR *name, size_t name_cch);

#endif
