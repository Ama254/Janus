#ifndef SELF_DELETION_H
#define SELF_DELETION_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/stat.h>

#define MAX_ARTIFACTS 1024
#define MAX_PATH_LEN 256
#define MAX_PAYLOAD_SIZE 8192
#define WIPE_PASSES 7
#define RANDOM_SEED 0xDEADBEEF

typedef struct {
    char artifact_path[MAX_PATH_LEN];
    int wipe_method;
    int priority;
} artifact_t;

typedef struct {
    artifact_t artifacts[MAX_ARTIFACTS];
    int artifact_count;
    char payload_path[MAX_PATH_LEN];
    size_t payload_size;
    int wipe_passes;
    int stealth_mode;
    int immediate_mode;
    int kernel_payload_deployed;
} self_deletion_ctx_t;

typedef enum {
    WIPE_ZERO = 0,
    WIPE_RANDOM = 1,
    WIPE_ONES = 2,
    WIPE_DOD = 3,
    WIPE_GUTMANN = 4,
    WIPE_SECURE = 5
} wipe_method_t;

int self_deletion_init(self_deletion_ctx_t *ctx);
int self_deletion_add_artifact(self_deletion_ctx_t *ctx, const char *path, int wipe_method, int priority);
int self_deletion_set_payload(self_deletion_ctx_t *ctx, const char *payload_path);
int self_deletion_execute(self_deletion_ctx_t *ctx);
int self_deletion_cleanup(self_deletion_ctx_t *ctx);

#endif