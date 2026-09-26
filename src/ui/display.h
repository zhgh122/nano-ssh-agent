#pragma once

#include <stdbool.h>  // bool

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#define ICON_APP_SSH  C_app_ssh_14px
#define ICON_APP_HOME C_home_ssh_14px
#elif defined(TARGET_STAX) || defined(TARGET_FLEX)
#define ICON_APP_SSH  C_app_ssh_64px
#define ICON_APP_HOME ICON_APP_SSH
#elif defined(TARGET_APEX_P)
#define ICON_APP_SSH  C_app_ssh_48px
#define ICON_APP_HOME ICON_APP_SSH
#endif
