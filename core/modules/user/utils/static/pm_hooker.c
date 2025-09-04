#include "advanced_package_hook.h"
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/time.h>

#define SYSCALL6(num, a1, a2, a3, a4, a5, a6) ({ \
    long ret; \
    asm volatile ( \
        "mov x0, %1\n" \
        "mov x1, %2\n" \
        "mov x2, %3\n" \
        "mov x3, %4\n" \
        "mov x4, %5\n" \
        "mov x5, %6\n" \
        "mov x8, %7\n" \
        "svc #0\n" \
        "mov %0, x0\n" \
        : "=r" (ret) \
        : "r" (a1), "r" (a2), "r" (a3), "r" (a4), "r" (a5), "r" (a6), "r" (num) \
        : "x0", "x1", "x2", "x3", "x4", "x5", "x8", "memory" \
    ); \
    ret; \
})

static int sys_open(const char *path, int flags, int mode) {
    return SYSCALL3(__NR_open, (long)path, flags, mode);
}

static int sys_close(int fd) {
    return SYSCALL1(__NR_close, fd);
}

static ssize_t sys_read(int fd, void *buf, size_t count) {
    return SYSCALL3(__NR_read, fd, (long)buf, count);
}

static void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return (void *)SYSCALL6(__NR_mmap, (long)addr, length, prot, flags, fd, offset);
}

static int sys_munmap(void *addr, size_t length) {
    return SYSCALL2(__NR_munmap, (long)addr, length);
}

static int sys_mprotect(void *addr, size_t len, int prot) {
    return SYSCALL3(__NR_mprotect, (long)addr, len, prot);
}

static unsigned long kallsyms_lookup_name(const char *name) {
    int fd = sys_open("/proc/kallsyms", O_RDONLY, 0);
    if (fd < 0) return 0;

    char buf[4096];
    ssize_t bytes = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);

    if (bytes <= 0) return 0;

    buf[bytes] = 0;
    char *ptr = buf;
    while (*ptr) {
        unsigned long addr;
        char symname[256];
        int count = 0;

        while (*ptr == ' ') ptr++;
        char *addr_start = ptr;
        while (*ptr && *ptr != ' ') ptr++;
        if (*ptr) *ptr++ = 0;
        addr = simple_strtoul(addr_start, NULL, 16);

        while (*ptr == ' ') ptr++;
        if (*ptr++ != 'T' && *ptr++ != 't') continue;

        while (*ptr == ' ') ptr++;
        char *name_start = ptr;
        while (*ptr && *ptr != '\n') ptr++;
        if (*ptr) *ptr++ = 0;

        int len = 0;
        while (name_start[len] && name_start[len] != ' ' && len < 255) {
            symname[len] = name_start[len];
            len++;
        }
        symname[len] = 0;

        if (strcmp(symname, name) == 0) {
            return addr;
        }
    }

    return 0;
}

static int pattern_match(const char *pattern, const char *string) {
    if (!pattern || !string) return 0;
    if (pattern[0] == '*') return 1;
    return strstr(string, pattern) != NULL;
}

static int is_trusted_uid(advanced_package_ctx_t *ctx, uid_t uid) {
    for (int i = 0; i < ctx->trusted_uid_count; i++) {
        if (ctx->trusted_uids[i] == uid) {
            return 1;
        }
    }
    return 0;
}

static int evaluate_rules(advanced_package_ctx_t *ctx, pm_action_t action, 
                         pm_transaction_data_t *data, rule_action_t *final_action,
                         pm_transaction_data_t *modified_data) {
    *final_action = RULE_ALLOW;
    
    for (int i = 0; i < ctx->rule_count; i++) {
        package_rule_t *rule = &ctx->rules[i];
        
        if (rule->action != action && rule->action != 0) continue;
        if (!pattern_match(rule->package_pattern, data->package_name)) continue;
        if (!pattern_match(rule->target_pattern, data->target_package)) continue;
        if (rule->required_uid != 0 && rule->required_uid != data->calling_uid) continue;
        if (rule->user_id_filter != -1 && rule->user_id_filter != data->user_id) continue;
        if (rule->install_flags_filter != 0 && (rule->install_flags_filter & data->install_flags) == 0) continue;

        *final_action = rule->rule_action;
        
        if (rule->rule_action == RULE_MODIFY || rule->rule_action == RULE_REDIRECT) {
            memcpy(modified_data, &rule->modified_data, sizeof(pm_transaction_data_t));
        }
        
        if (rule->rule_action == RULE_INJECT && rule->custom_handler) {
            rule->custom_handler(data);
        }
        
        if (rule->rule_action != RULE_ALLOW) {
            break;
        }
    }
    
    if (ctx->block_all_foreign && !is_trusted_uid(ctx, data->calling_uid)) {
        *final_action = RULE_BLOCK;
    }
    
    return 0;
}

static void modify_transaction_data(struct binder_transaction_data *tr, 
                                   const pm_transaction_data_t *new_data) {
    size_t new_size = sizeof(pm_transaction_data_t);
    if (tr->data_size < new_size) {
        return;
    }
    
    memcpy((void *)tr->data.ptr.buffer, new_data, new_size);
}

static void inject_package_install(advanced_package_ctx_t *ctx, const char *apk_path) {
    int fd = sys_open(apk_path, O_RDONLY, 0);
    if (fd < 0) return;

    struct stat st;
    if (sys_fstat(fd, &st) < 0) {
        sys_close(fd);
        return;
    }

    void *apk_data = sys_mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (apk_data == MAP_FAILED) {
        sys_close(fd);
        return;
    }

    struct binder_transaction_data tr = {
        .target.handle = ctx->pms_handle,
        .code = PM_ACTION_INSTALL,
        .flags = TF_ACCEPT_FDS,
        .data_size = st.st_size,
        .data.ptr.buffer = (binder_uintptr_t)apk_data,
        .offsets_size = 0
    };

    long (*orig_transact)(struct binder_transaction_data *) = 
        (long (*)(struct binder_transaction_data *))ctx->orig_binder_transact;
    orig_transact(&tr);

    sys_munmap(apk_data, st.st_size);
    sys_close(fd);
}

static long hooked_binder_transact(struct binder_transaction_data *tr) {
    advanced_package_ctx_t *ctx = (advanced_package_ctx_t *)binder_get_context();
    long (*orig_transact)(struct binder_transaction_data *) = 
        (long (*)(struct binder_transaction_data *))ctx->orig_binder_transact;

    if (!ctx->enabled || tr->target.handle != ctx->pms_handle) {
        return orig_transact(tr);
    }

    pm_action_t action = (pm_action_t)tr->code;
    pm_transaction_data_t data;
    
    if (tr->data_size >= sizeof(pm_transaction_data_t)) {
        memcpy(&data, (void *)tr->data.ptr.buffer, sizeof(pm_transaction_data_t));
    } else {
        memset(&data, 0, sizeof(pm_transaction_data_t));
    }

    rule_action_t final_action;
    pm_transaction_data_t modified_data;
    
    evaluate_rules(ctx, action, &data, &final_action, &modified_data);

    switch (final_action) {
        case RULE_BLOCK:
            return -EPERM;
            
        case RULE_REDIRECT:
            modify_transaction_data(tr, &modified_data);
            break;
            
        case RULE_MODIFY:
            modify_transaction_data(tr, &modified_data);
            return orig_transact(tr);
            
        case RULE_INJECT:
            if (action == PM_ACTION_INSTALL) {
                inject_package_install(ctx, modified_data.apk_path);
            }
            return 0;
            
        case RULE_DELAY:
            {
                struct timespec req = {
                    .tv_sec = modified_data.delay_ms / 1000,
                    .tv_nsec = (modified_data.delay_ms % 1000) * 1000000
                };
                asm volatile (
                    "mov x0, %0\n"
                    "mov x8, #35\n"
                    "svc #0\n"
                    :
                    : "r" (&req)
                    : "x0", "x8", "memory"
                );
            }
            break;
            
        case RULE_ALLOW:
        default:
            break;
    }

    return orig_transact(tr);
}

static int hook_binder_transaction(advanced_package_ctx_t *ctx) {
    unsigned long binder_transact_addr = kallsyms_lookup_name("binder_transaction");
    if (!binder_transact_addr) return -1;

    ctx->orig_binder_transact = binder_transact_addr;

    unsigned long pms_service_addr = kallsyms_lookup_name("package_manager_service");
    if (!pms_service_addr) return -1;

    struct binder_service *pms_service = (struct binder_service *)pms_service_addr;
    ctx->pms_handle = pms_service->handle;

    unsigned long hooked_transact = (unsigned long)hooked_binder_transact;

    sys_mprotect((void *)binder_transact_addr, sizeof(unsigned long), PROT_READ | PROT_WRITE);
    *(unsigned long *)binder_transact_addr = hooked_transact;
    sys_mprotect((void *)binder_transact_addr, sizeof(unsigned long), PROT_READ);

    return 0;
}

int advanced_package_hook_init(advanced_package_ctx_t *ctx) {
    memset(ctx, 0, sizeof(advanced_package_ctx_t));
    
    if (hook_binder_transaction(ctx) < 0) {
        return -1;
    }

    ctx->enabled = 1;
    ctx->trusted_uids[0] = 0;
    ctx->trusted_uids[1] = 1000;
    ctx->trusted_uids[2] = 1001;
    ctx->trusted_uid_count = 3;

    return 0;
}

int advanced_package_add_rule(advanced_package_ctx_t *ctx, const package_rule_t *rule) {
    if (ctx->rule_count >= MAX_PACKAGE_RULES) return -1;

    memcpy(&ctx->rules[ctx->rule_count++], rule, sizeof(package_rule_t));
    return 0;
}

int advanced_package_remove_rule(advanced_package_ctx_t *ctx, int index) {
    if (index < 0 || index >= ctx->rule_count) return -1;

    for (int i = index; i < ctx->rule_count - 1; i++) {
        memcpy(&ctx->rules[i], &ctx->rules[i + 1], sizeof(package_rule_t));
    }
    ctx->rule_count--;

    return 0;
}

int advanced_package_enable(advanced_package_ctx_t *ctx) {
    ctx->enabled = 1;
    return 0;
}

int advanced_package_disable(advanced_package_ctx_t *ctx) {
    ctx->enabled = 0;
    return 0;
}

int advanced_package_cleanup(advanced_package_ctx_t *ctx) {
    if (ctx->orig_binder_transact) {
        sys_mprotect((void *)ctx->orig_binder_transact, sizeof(unsigned long), PROT_READ | PROT_WRITE);
        *(unsigned long *)ctx->orig_binder_transact = ctx->orig_binder_transact;
        sys_mprotect((void *)ctx->orig_binder_transact, sizeof(unsigned long), PROT_READ);
    }

    memset(ctx, 0, sizeof(advanced_package_ctx_t));
    return 0;
}