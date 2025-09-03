// advanced_fsmonitor.c
#include "advanced_fsmonitor.h"

// System call wrappers with ARM64 assembly
#define SYSCALL3(num, arg1, arg2, arg3) ({ \
    long ret; \
    asm volatile ( \
        "mov x0, %1\n" \
        "mov x1, %2\n" \
        "mov x2, %3\n" \
        "mov x8, %4\n" \
        "svc #0\n" \
        "mov %0, x0\n" \
        : "=r" (ret) \
        : "r" (arg1), "r" (arg2), "r" (arg3), "r" (num) \
        : "x0", "x1", "x2", "x8", "memory" \
    ); \
    ret; \
})

#define SYSCALL2(num, arg1, arg2) ({ \
    long ret; \
    asm volatile ( \
        "mov x0, %1\n" \
        "mov x1, %2\n" \
        "mov x8, %3\n" \
        "svc #0\n" \
        "mov %0, x0\n" \
        : "=r" (ret) \
        : "r" (arg1), "r" (arg2), "r" (num) \
        : "x0", "x1", "x8", "memory" \
    ); \
    ret; \
})

#define SYSCALL1(num, arg1) ({ \
    long ret; \
    asm volatile ( \
        "mov x0, %1\n" \
        "mov x8, %2\n" \
        "svc #0\n" \
        "mov %0, x0\n" \
        : "=r" (ret) \
        : "r" (arg1), "r" (num) \
        : "x0", "x8", "memory" \
    ); \
    ret; \
})

static int sys_open(const char *pathname, int flags, mode_t mode) {
    return SYSCALL3(__NR_open, (long)pathname, flags, mode);
}

static int sys_close(int fd) {
    return SYSCALL1(__NR_close, fd);
}

static int sys_ioctl(int fd, unsigned long request, void *arg) {
    return SYSCALL3(__NR_ioctl, fd, request, (long)arg);
}

static ssize_t sys_read(int fd, void *buf, size_t count) {
    return SYSCALL3(__NR_read, fd, (long)buf, count);
}

static off_t sys_lseek(int fd, off_t offset, int whence) {
    return SYSCALL3(__NR_lseek, fd, offset, whence);
}

static int sys_stat(const char *path, struct kstat *statbuf) {
    return SYSCALL2(__NR_stat, (long)path, (long)statbuf);
}

static int sys_fstat(int fd, struct kstat *statbuf) {
    return SYSCALL2(__NR_fstat, fd, (long)statbuf);
}

static int sys_inotify_init1(int flags) {
    return SYSCALL1(__NR_inotify_init1, flags);
}

static int sys_inotify_add_watch(int fd, const char *path, uint32_t mask) {
    return SYSCALL3(__NR_inotify_add_watch, fd, (long)path, mask);
}

static int sys_inotify_rm_watch(int fd, int wd) {
    return SYSCALL2(__NR_inotify_rm_watch, fd, wd);
}

// Advanced filesystem monitoring implementation
int afsmonitor_init(advanced_fsmonitor_ctx_t *ctx) {
    ctx->inotify_fd = sys_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ctx->inotify_fd < 0) return -1;

    ctx->fanotify_fd = -1;
    ctx->audit_fd = -1;
    ctx->watch_count = 0;
    ctx->journal_count = 0;
    ctx->running = 0;
    ctx->event_sequence = 0;
    
    for (int i = 0; i < MAX_WATCH_PATHS; i++) {
        ctx->watches[i].wd = -1;
    }
    
    for (int i = 0; i < MAX_JOURNAL_PATHS; i++) {
        ctx->journals[i].journal_fd = -1;
    }
    
    return 0;
}

int afsmonitor_add_watch(advanced_fsmonitor_ctx_t *ctx, const char *path, uint32_t mask) {
    if (ctx->watch_count >= MAX_WATCH_PATHS) return -1;

    struct kstat statbuf;
    if (sys_stat(path, &statbuf) < 0) return -1;

    int wd = sys_inotify_add_watch(ctx->inotify_fd, path, mask);
    if (wd < 0) return -1;

    int slot = -1;
    for (int i = 0; i < MAX_WATCH_PATHS; i++) {
        if (ctx->watches[i].wd == -1) {
            slot = i;
            break;
        }
    }
    if (slot == -1) {
        sys_inotify_rm_watch(ctx->inotify_fd, wd);
        return -1;
    }

    int len = 0;
    while (path[len] && len < PATH_MAX - 1) {
        ctx->watches[slot].path[len] = path[len];
        len++;
    }
    ctx->watches[slot].path[len] = '\0';
    ctx->watches[slot].wd = wd;
    ctx->watches[slot].mask = mask;
    ctx->watches[slot].inode = statbuf.st_ino;
    ctx->watches[slot].device = statbuf.st_dev;
    ctx->watch_count++;

    return wd;
}

int afsmonitor_add_journal(advanced_fsmonitor_ctx_t *ctx, const char *journal_path) {
    if (ctx->journal_count >= MAX_JOURNAL_PATHS) return -1;

    int fd = sys_open(journal_path, O_RDONLY | O_LARGEFILE, 0);
    if (fd < 0) return -1;

    struct kstat statbuf;
    if (sys_fstat(fd, &statbuf) < 0) {
        sys_close(fd);
        return -1;
    }

    int slot = -1;
    for (int i = 0; i < MAX_JOURNAL_PATHS; i++) {
        if (ctx->journals[i].journal_fd == -1) {
            slot = i;
            break;
        }
    }
    if (slot == -1) {
        sys_close(fd);
        return -1;
    }

    int len = 0;
    while (journal_path[len] && len < PATH_MAX - 1) {
        ctx->journals[slot].journal_path[len] = journal_path[len];
        len++;
    }
    ctx->journals[slot].journal_path[len] = '\0';
    ctx->journals[slot].journal_fd = fd;
    ctx->journals[slot].journal_size = statbuf.st_size;
    ctx->journals[slot].last_transaction_id = 0;

    // Detect filesystem type
    char fstype[16] = {0};
    if (afsmonitor_detect_filesystem(journal_path, fstype, sizeof(fstype)) == 0) {
        ctx->journals[slot].is_ext4 = (strcmp(fstype, "ext4") == 0);
        ctx->journals[slot].is_f2fs = (strcmp(fstype, "f2fs") == 0);
    }

    ctx->journal_count++;
    return 0;
}

int afsmonitor_detect_filesystem(const char *path, char *fstype, size_t fstype_len) {
    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) return -1;

    struct ext4_super_block sb;
    if (sys_read(fd, &sb, sizeof(sb)) != sizeof(sb)) {
        sys_close(fd);
        return -1;
    }

    if (sb.s_magic == EXT4_SUPER_MAGIC) {
        strncpy(fstype, "ext4", fstype_len);
    } else {
        // Check other filesystems
        strncpy(fstype, "unknown", fstype_len);
    }

    sys_close(fd);
    return 0;
}

static void parse_ext4_journal(advanced_fsmonitor_ctx_t *ctx, journal_info_t *journal) {
    struct ext4_super_block sb;
    sys_lseek(journal->journal_fd, 1024, SEEK_SET);
    sys_read(journal->journal_fd, &sb, sizeof(sb));

    if (sb.s_magic != EXT4_SUPER_MAGIC) return;

    // Parse journal superblock
    struct ext4_super_block j_sb;
    off_t journal_start = sb.s_journal_inum ? sb.s_journal_inum : sb.s_first_data_block + 1;
    sys_lseek(journal->journal_fd, journal_start * 1024, SEEK_SET);
    sys_read(journal->journal_fd, &j_sb, sizeof(j_sb));

    // Read journal transactions
    uint32_t block_size = 1024 << sb.s_log_block_size;
    char *journal_buffer = malloc(block_size);
    
    for (uint64_t trans_id = journal->last_transaction_id + 1; ; trans_id++) {
        off_t trans_offset = journal_start * 1024 + trans_id * block_size;
        if (trans_offset >= journal->journal_size) break;

        sys_lseek(journal->journal_fd, trans_offset, SEEK_SET);
        ssize_t read = sys_read(journal->journal_fd, journal_buffer, block_size);
        if (read != block_size) break;

        // Parse journal transaction
        if (ctx->journal_callback) {
            ctx->journal_callback(journal->journal_path, trans_id, 
                                 "JOURNAL_TRANSACTION", "", "Ext4 journal entry", 1);
        }
        
        journal->last_transaction_id = trans_id;
    }
    
    free(journal_buffer);
}

static void process_inotify_events(advanced_fsmonitor_ctx_t *ctx) {
    char buffer[MAX_EVENT_BUFFER_SIZE * MAX_EVENTS_PER_READ];
    ssize_t length = sys_read(ctx->inotify_fd, buffer, sizeof(buffer));
    if (length <= 0) return;

    char *ptr = buffer;
    while (ptr < buffer + length) {
        struct inotify_event *event = (struct inotify_event *)ptr;
        ctx->event_sequence++;

        for (int i = 0; i < MAX_WATCH_PATHS; i++) {
            if (ctx->watches[i].wd == event->wd) {
                if (ctx->fs_callback) {
                    char details[256];
                    snprintf(details, sizeof(details), 
                            "seq=%lu mask=%x cookie=%x", 
                            ctx->event_sequence, event->mask, event->cookie);
                    
                    ctx->fs_callback(ctx->watches[i].path, event->mask, 
                                   event->len > 0 ? event->name : "",
                                   ctx->watches[i].inode, ctx->watches[i].device,
                                   details);
                }
                break;
            }
        }
        ptr += sizeof(struct inotify_event) + event->len;
    }
}

static void process_journals(advanced_fsmonitor_ctx_t *ctx) {
    for (int i = 0; i < ctx->journal_count; i++) {
        if (ctx->journals[i].is_ext4) {
            parse_ext4_journal(ctx, &ctx->journals[i]);
        }
    }
}

int afsmonitor_start(advanced_fsmonitor_ctx_t *ctx) {
    if (ctx->running) return -1;
    ctx->running = 1;

    while (ctx->running) {
        process_inotify_events(ctx);
        process_journals(ctx);

        // High-precision sleep using clock_nanosleep
        struct timespec req = {0, 10000000}; // 10ms
        asm volatile (
            "mov x0, %0\n"
            "mov x1, 0\n"
            "mov x8, #35\n"
            "svc #0\n"
            :
            : "r" (&req)
            : "x0", "x1", "x8", "memory"
        );
    }
    return 0;
}

int afsmonitor_stop(advanced_fsmonitor_ctx_t *ctx) {
    ctx->running = 0;
    return 0;
}

void afsmonitor_cleanup(advanced_fsmonitor_ctx_t *ctx) {
    for (int i = 0; i < MAX_WATCH_PATHS; i++) {
        if (ctx->watches[i].wd != -1) {
            sys_inotify_rm_watch(ctx->inotify_fd, ctx->watches[i].wd);
        }
    }
    
    for (int i = 0; i < MAX_JOURNAL_PATHS; i++) {
        if (ctx->journals[i].journal_fd != -1) {
            sys_close(ctx->journals[i].journal_fd);
        }
    }
    
    if (ctx->inotify_fd >= 0) sys_close(ctx->inotify_fd);
    if (ctx->fanotify_fd >= 0) sys_close(ctx->fanotify_fd);
    if (ctx->audit_fd >= 0) sys_close(ctx->audit_fd);
    
    ctx->inotify_fd = -1;
    ctx->fanotify_fd = -1;
    ctx->audit_fd = -1;
    ctx->watch_count = 0;
    ctx->journal_count = 0;
}