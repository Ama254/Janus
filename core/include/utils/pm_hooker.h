#ifndef ADVANCED_PACKAGE_HOOK_H
#define ADVANCED_PACKAGE_HOOK_H

#include <linux/types.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/binder.h>
#include <linux/android/binder.h>
#include <linux/errno.h>

#define MAX_PACKAGE_RULES 512
#define MAX_PACKAGE_NAME 256
#define MAX_APK_PATH 512
#define MAX_INTENT_FILTERS 128
#define MAX_PERMISSIONS 256

typedef enum {
    PM_ACTION_INSTALL = 1,
    PM_ACTION_UNINSTALL = 2,
    PM_ACTION_DELETE = 3,
    PM_ACTION_UPDATE = 4,
    PM_ACTION_QUERY = 5,
    PM_ACTION_GRANT_PERM = 6,
    PM_ACTION_REVOKE_PERM = 7,
    PM_ACTION_SET_COMPONENT = 8,
    PM_ACTION_CLEAR_DATA = 9,
    PM_ACTION_FORCE_STOP = 10
} pm_action_t;

typedef enum {
    RULE_ALLOW = 0,
    RULE_BLOCK = 1,
    RULE_REDIRECT = 2,
    RULE_MODIFY = 3,
    RULE_INJECT = 4,
    RULE_DELAY = 5
} rule_action_t;

typedef struct {
    char package_name[MAX_PACKAGE_NAME];
    char target_package[MAX_PACKAGE_NAME];
    char apk_path[MAX_APK_PATH];
    char permission[MAX_PACKAGE_NAME];
    char component[MAX_PACKAGE_NAME];
    uid_t calling_uid;
    int user_id;
    int install_flags;
    int permission_flags;
    long delay_ms;
} pm_transaction_data_t;

typedef struct {
    pm_action_t action;
    rule_action_t rule_action;
    char package_pattern[MAX_PACKAGE_NAME];
    char target_pattern[MAX_PACKAGE_NAME];
    uid_t required_uid;
    int user_id_filter;
    int install_flags_filter;
    pm_transaction_data_t modified_data;
    void (*custom_handler)(pm_transaction_data_t *);
} package_rule_t;

typedef struct {
    package_rule_t rules[MAX_PACKAGE_RULES];
    int rule_count;
    unsigned long orig_binder_transact;
    unsigned long pms_handle;
    int stealth_mode;
    int enabled;
    int block_all_foreign;
    uid_t trusted_uids[16];
    int trusted_uid_count;
} advanced_package_ctx_t;

int advanced_package_hook_init(advanced_package_ctx_t *ctx);
int advanced_package_add_rule(advanced_package_ctx_t *ctx, const package_rule_t *rule);
int advanced_package_remove_rule(advanced_package_ctx_t *ctx, int index);
int advanced_package_enable(advanced_package_ctx_t *ctx);
int advanced_package_disable(advanced_package_ctx_t *ctx);
int advanced_package_cleanup(advanced_package_ctx_t *ctx);

#endif