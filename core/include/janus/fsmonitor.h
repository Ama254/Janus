// advanced_fsmonitor.h
#ifndef ADVANCED_FSMONITOR_H
#define ADVANCED_FSMONITOR_H

#include <linux/types.h>
#include <linux/inotify.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/ext4_fs.h>

#define MAX_WATCH_PATHS 256
#define MAX_EVENT_BUFFER_SIZE (sizeof(struct inotify_event) + NAME_MAX + 1)
#define MAX_EVENTS_PER_READ 512
#define JOURNAL_BLOCK_SIZE 4096
#define MAX_JOURNAL_PATHS 32
#define FIEMAP_MAX_EXTENTS 256

typedef struct {
    char path[PATH_MAX];
    int wd;
    uint32_t mask;
    ino_t inode;
    dev_t device;
} watch_entry_t;

typedef struct {
    char journal_path[PATH_MAX];
    int journal_fd;
    off_t journal_size;
    uint64_t last_transaction_id;
    int is_ext4;
    int is_f2fs;
} journal_info_t;

typedef struct {
    // Inotify context
    int inotify_fd;
    watch_entry_t watches[MAX_WATCH_PATHS];
    int watch_count;
    
    // Journal context
    journal_info_t journals[MAX_JOURNAL_PATHS];
    int journal_count;
    
    // Advanced monitoring
    int fanotify_fd;
    int audit_fd;
    
    // Callbacks
    void (*fs_callback)(const char *path, uint32_t mask, const char *filename, 
                       ino_t inode, dev_t device, const char *event_details);
    void (*journal_callback)(const char *journal_path, uint64_t transaction_id,
                            const char *operation, const char *path, 
                            const char *details, int is_metadata);
    
    volatile int running;
    uint64_t event_sequence;
} advanced_fsmonitor_ctx_t;

// Public API
int afsmonitor_init(advanced_fsmonitor_ctx_t *ctx);
int afsmonitor_add_watch(advanced_fsmonitor_ctx_t *ctx, const char *path, uint32_t mask);
int afsmonitor_add_journal(advanced_fsmonitor_ctx_t *ctx, const char *journal_path);
int afsmonitor_enable_fanotify(advanced_fsmonitor_ctx_t *ctx);
int afsmonitor_enable_audit(advanced_fsmonitor_ctx_t *ctx);
int afsmonitor_start(advanced_fsmonitor_ctx_t *ctx);
int afsmonitor_stop(advanced_fsmonitor_ctx_t *ctx);
void afsmonitor_cleanup(advanced_fsmonitor_ctx_t *ctx);

// Utility functions
uint64_t afsmonitor_get_inode_details(const char *path, struct kstat *stat);
int afsmonitor_get_file_extents(int fd, struct fiemap *fiemap);
int afsmonitor_detect_filesystem(const char *path, char *fstype, size_t fstype_len);

// Event masks
#define AFSMONITOR_ALL_EVENTS (IN_ALL_EVENTS | IN_ONLYDIR | IN_DONT_FOLLOW)
#define AFSMONITOR_DEEP_MONITOR 0x80000000

#endif