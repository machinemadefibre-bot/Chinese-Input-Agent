#ifndef CHINESE_INPUT_AGENT_APP_CARRIER_OPTIONS_H
#define CHINESE_INPUT_AGENT_APP_CARRIER_OPTIONS_H

#include <windows.h>

typedef enum APP_CARRIER_REDUNDANCY_LEVEL {
    APP_CARRIER_REDUNDANCY_NONE = 0,
    APP_CARRIER_REDUNDANCY_LOW = 1,
    APP_CARRIER_REDUNDANCY_MEDIUM = 2,
    APP_CARRIER_REDUNDANCY_HIGH = 3
} APP_CARRIER_REDUNDANCY_LEVEL;

typedef struct APP_CARRIER_OPTIONS {
    const WCHAR *custom_prompt_text;
    BOOL has_temperature;
    double temperature;
    BOOL has_top_p;
    double top_p;
    APP_CARRIER_REDUNDANCY_LEVEL redundancy_level;
} APP_CARRIER_OPTIONS;

#endif
