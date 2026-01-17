#include <android/log.h>
#include <cstring>
#include <cstdlib>
#include <cstdarg>
#include <vector>
#include <link.h>
#include <sys/auxv.h>
#include "zygisk_next_api.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "zn-auditpatch", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "zn-auditpatch", __VA_ARGS__)

static ZygiskNextAPI api_table;

static int (*old_vasprintf)(char **strp, const char *fmt, va_list ap) = nullptr;

static bool has_quote_after(const char *pos, size_t match_len) {
    const char *end = pos + match_len;
    while (*end != '\0') {
        if (*end == '"') {
            return true;
        }
        end++;
    }
    return false;
}

static int my_vasprintf(char **strp, const char *fmt, va_list ap) {
    // https://cs.android.com/android/platform/superproject/main/+/main:system/logging/logd/LogAudit.cpp;l=210
    auto result = old_vasprintf(strp, fmt, ap);

    if (result > 0 && *strp) {
        // https://cs.android.com/android/platform/superproject/main/+/main:external/selinux/libselinux/src/android/android_seapp.c;l=694
        constexpr std::string_view target_context = "tcontext=u:r:priv_app:s0:c512,c768";
        constexpr std::string_view source_contexts[] = {
                "tcontext=u:r:su:s0",
                "tcontext=u:r:magisk:s0"
        };

        for (const auto &source: source_contexts) {
            char *pos = strstr(*strp, source.data());

            if (pos && !has_quote_after(pos, source.size())) {
                size_t extra_space = (target_context.size() > source.size()) ?
                                     (target_context.size() - source.size()) : 0;

                // Reverse double space in case
                char *new_str = static_cast<char *>(malloc(result + 2 * extra_space + 1));

                strcpy(new_str, *strp);
                pos = new_str + (pos - *strp);

                if (source.size() != target_context.size()) {
                    memmove(pos + target_context.size(), pos + source.size(),
                            strlen(pos + source.size()) + 1);
                }
                memcpy(pos, target_context.data(), target_context.size());

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

    void* base = nullptr;
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t sz, void* data) -> int {
        auto linker_base = (uintptr_t) getauxval(AT_BASE);
        if (linker_base == info->dlpi_addr)
            return 0;
        *reinterpret_cast<void**>(data) = (void*) info->dlpi_addr;
        return 1;
    }, &base);

    auto ret = api_table.pltHook(base, "vasprintf", (void *) my_vasprintf, (void **) &old_vasprintf);
    if (ret == ZN_SUCCESS) {
        LOGI("logd PLT hook success");
    } else {
        LOGE("logd PLT hook failure, code: %d", ret);
    }
}

__attribute__((visibility("default"), unused))
struct ZygiskNextModule zn_module = {
        .target_api_version = ZYGISK_NEXT_API_VERSION_1,
        .onModuleLoaded = onModuleLoaded,
};
