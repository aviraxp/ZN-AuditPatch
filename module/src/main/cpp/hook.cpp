#include <android/log.h>
#include <cstring>
#include <cstdlib>
#include <cstdarg>
#include <vector>
#include "zygisk_next_api.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "zn-auditpatch", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "zn-auditpatch", __VA_ARGS__)

static ZygiskNextAPI api_table;
void *handle;

static int (*old_vasprintf)(char **strp, const char *fmt, va_list ap) = nullptr;

static bool is_in_quotes(const char *str, const char *pos) {
    bool in_quote = false;
    for (const char *p = str; p < pos; p++) {
        if (*p == '"') {
            in_quote = !in_quote;
        }
    }
    return in_quote;
}

static int my_vasprintf(char **strp, const char *fmt, va_list ap) {
    // https://cs.android.com/android/platform/superproject/main/+/main:system/logging/logd/LogAudit.cpp;l=210
    auto result = old_vasprintf(strp, fmt, ap);

    if (result > 0 && *strp) {
        const char *target_context = "tcontext=u:r:kernel:s0";

        std::vector<const char *> source_contexts = {
                "tcontext=u:r:su:s0",
                "tcontext=u:r:magisk:s0"
        };

        size_t target_len = strlen(target_context);

        for (const char *source: source_contexts) {
            char *pos = strstr(*strp, source);

            if (pos && !is_in_quotes(*strp, pos)) {
                size_t source_len = strlen(source);
                size_t extra_space = (target_len > source_len) ? (target_len - source_len) : 0;

                // Reverse double space in case
                char *new_str = static_cast<char *>(malloc(result + 2 * extra_space + 1));
                strcpy(new_str, *strp);
                pos = new_str + (pos - *strp);

                if (source_len != target_len) {
                    memmove(pos + target_len, pos + source_len, strlen(pos + source_len) + 1);
                }
                memcpy(pos, target_context, target_len);

                free(*strp);
                *strp = new_str;
                return static_cast<int>(strlen(new_str));
            }
        }
    }

    return result;
}

void onModuleLoaded(void *self_handle, const struct ZygiskNextAPI *api) {
    memcpy(&api_table, api, sizeof(ZygiskNextAPI));

    auto resolver = api_table.newSymbolResolver("libc.so", nullptr);
    if (!resolver) return;

    size_t sz;
    auto addr = api_table.symbolLookup(resolver, "vasprintf", false, &sz);
    api_table.freeSymbolResolver(resolver);

    if (addr &&
        api_table.inlineHook(addr, (void *) my_vasprintf, (void **) &old_vasprintf) == ZN_SUCCESS) {
        LOGI("logd hook success");
    } else {
        LOGE("logd hook failure");
    }
}

__attribute__((visibility("default")))
struct ZygiskNextModule zn_module = {
        .target_api_version = ZYGISK_NEXT_API_VERSION_1,
        .onModuleLoaded = onModuleLoaded,
};
