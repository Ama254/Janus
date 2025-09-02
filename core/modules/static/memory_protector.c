#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <pthread.h>
#include <time.h>
#include <sys/prctl.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/eventfd.h>
#include <sys/random.h>
#include <sys/timerfd.h>
#include <poll.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <linux/audit.h>
#include <sys/capability.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/inotify.h>
#include <linux/seccomp.h>
#include <sys/resource.h>
#include <elf.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <sys/xattr.h>
#include <linux/perf_event.h>
#include <sys/vfs.h>
#include <sys/time.h>

#define MAX_PROTECTED_REGIONS 64
#define MAX_VIOLATIONS 256
#define CANARY_SIZE 64
#define ENTROPY_POOL_SIZE 8192
#define INTEGRITY_CHECK_INTERVAL_MS 50
#define MEMORY_SCAN_INTERVAL_MS 75
#define VIOLATION_THRESHOLD 3
#define MAX_STACK_FRAMES 64
#define PAGE_SIZE 4096
#define WATCHDOG_INTERVAL_MS 100
#define MAX_BACKUP_COPIES 3
#define MAX_TRUSTED_PROCESSES 32
#define NETLINK_BUFFER_SIZE 8192
#define MAX_KERNEL_CALLBACKS 16
#define TELEMETRY_BUFFER_SIZE 4096
#define MAX_HOOK_POINTS 32
#define THREAT_INTELLIGENCE_UPDATE_INTERVAL 3600
#define MIN_CHECK_INTERVAL_MS 25
#define MAX_CHECK_INTERVAL_MS 500
#define ADAPTIVE_CHECK_INTERVAL_STEP 5

typedef struct {
    void* address;
    size_t size;
    unsigned char canary_pre[CANARY_SIZE];
    unsigned char canary_post[CANARY_SIZE];
    unsigned char hmac[SHA256_DIGEST_LENGTH];
    int flags;
    uint64_t check_count;
    time_t last_check;
    int index;
} protected_region_t;

typedef struct {
    pid_t pid;
    uid_t uid;
    gid_t gid;
    void* addr;
    time_t timestamp;
    unsigned char stack_hash[SHA256_DIGEST_LENGTH];
    char comm[32];
    int severity;
    uint64_t violation_count;
} violation_record_t;

typedef struct {
    void* stack[MAX_STACK_FRAMES];
    int depth;
    unsigned char hash[SHA256_DIGEST_LENGTH];
} stack_trace_t;

typedef struct {
    unsigned char original_hash[SHA256_DIGEST_LENGTH];
    unsigned char backup_hash[SHA256_DIGEST_LENGTH];
    void* backup_location;
    size_t backup_size;
    time_t backup_time;
} memory_backup_t;

typedef struct {
    pid_t pid;
    uid_t uid;
    char comm[32];
    unsigned char binary_hash[SHA256_DIGEST_LENGTH];
    time_t last_verified;
    int trust_level;
    int fd;
    ino_t inode;
    dev_t device;
} trusted_process_t;

typedef struct {
    void* address;
    unsigned char original_bytes[16];
    unsigned char current_bytes[16];
    size_t hook_size;
    int status;
    int is_trampoline;
} hook_point_t;

typedef struct {
    int type;
    time_t timestamp;
    char description[256];
    unsigned char evidence_hash[SHA256_DIGEST_LENGTH];
    int severity;
    void* context;
} telemetry_event_t;

typedef struct {
    protected_region_t regions[MAX_PROTECTED_REGIONS];
    int region_count;
    violation_record_t violations[MAX_VIOLATIONS];
    int violation_count;
    
    memory_backup_t backups[MAX_PROTECTED_REGIONS][MAX_BACKUP_COPIES];
    trusted_process_t trusted_processes[MAX_TRUSTED_PROCESSES];
    int trusted_process_count;
    
    hook_point_t hooks[MAX_HOOK_POINTS];
    int hook_count;
    
    pthread_mutex_t region_lock;
    pthread_mutex_t violation_lock;
    pthread_mutex_t backup_lock;
    pthread_mutex_t telemetry_lock;
    pthread_rwlock_t region_rwlock;
    
    pthread_t monitor_thread;
    pthread_t watchdog_thread;
    pthread_t netlink_thread;
    
    int event_fd;
    int timer_fd;
    int inotify_fd;
    int netlink_socket;
    int kernel_event_pipe[2];
    int perf_fds[8];
    int heartbeat_socket;
    
    volatile sig_atomic_t active;
    volatile sig_atomic_t self_test_status;
    
    unsigned char entropy_pool[ENTROPY_POOL_SIZE];
    size_t entropy_index;
    EVP_CIPHER_CTX *cipher_ctx;
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char runtime_encryption_key[32];
    
    uint64_t integrity_checks;
    struct timespec last_check;
    time_t last_key_rotation;
    time_t last_self_test;
    
    telemetry_event_t* telemetry_buffer;
    int telemetry_count;
    
    void (*kernel_callbacks[MAX_KERNEL_CALLBACKS])(void*);
    struct perf_event_attr perf_attrs[8];
    
    char edr_binary_path[PATH_MAX];
    unsigned char edr_binary_hash[SHA256_DIGEST_LENGTH];
    struct sockaddr_in remote_server;
    
    int current_check_interval;
    uint64_t total_scan_time_ns;
    uint64_t scan_count;
} enhanced_protector_t;

static enhanced_protector_t protector;

static int crypto_operation_safe(EVP_CIPHER_CTX* ctx, const unsigned char* in, unsigned char* out, size_t len, int encrypt) {
    if (!ctx || !in || !out || len == 0) return 0;
    
    int outlen, finallen;
    if (encrypt) {
        if (!EVP_EncryptUpdate(ctx, out, &outlen, in, len)) return 0;
        if (!EVP_EncryptFinal_ex(ctx, out + outlen, &finallen)) return 0;
    } else {
        if (!EVP_DecryptUpdate(ctx, out, &outlen, in, len)) return 0;
        if (!EVP_DecryptFinal_ex(ctx, out + outlen, &finallen)) return 0;
    }
    return 1;
}

static void update_entropy() {
    ssize_t bytes_read = getrandom(protector.entropy_pool, ENTROPY_POOL_SIZE, GRND_NONBLOCK);
    if (bytes_read != ENTROPY_POOL_SIZE) {
        FILE *urandom = fopen("/dev/urandom", "rb");
        if (urandom) {
            if (fread(protector.entropy_pool, 1, ENTROPY_POOL_SIZE, urandom) != ENTROPY_POOL_SIZE) {
                memset(protector.entropy_pool, 0, ENTROPY_POOL_SIZE);
            }
            fclose(urandom);
        } else {
            memset(protector.entropy_pool, 0, ENTROPY_POOL_SIZE);
        }
    }

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned char time_data[sizeof(ts)];
    memcpy(time_data, &ts, sizeof(ts));
    
    for (size_t i = 0; i < sizeof(ts); i++) {
        protector.entropy_pool[i] ^= time_data[i];
    }

    SHA256_CTX sha_ctx;
    if (!SHA256_Init(&sha_ctx) || 
        !SHA256_Update(&sha_ctx, protector.entropy_pool, ENTROPY_POOL_SIZE) ||
        !SHA256_Final(protector.entropy_pool, &sha_ctx)) {
        memset(protector.entropy_pool, 0, ENTROPY_POOL_SIZE);
    }
}

static void generate_canary(unsigned char *canary, size_t size) {
    if (size > CANARY_SIZE) size = CANARY_SIZE;
    
    pthread_mutex_lock(&protector.region_lock);
    update_entropy();
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        pthread_mutex_unlock(&protector.region_lock);
        memset(canary, 0, size);
        return;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, protector.key, protector.iv)) {
        int outlen;
        EVP_EncryptUpdate(ctx, canary, &outlen, protector.entropy_pool, size);
    } else {
        memset(canary, 0, size);
    }
    
    EVP_CIPHER_CTX_free(ctx);
    pthread_mutex_unlock(&protector.region_lock);
}

static int compute_hash(void* data, size_t size, unsigned char* hash) {
    if (!data || size == 0 || !hash) return 0;
    
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx) || 
        !SHA256_Update(&ctx, data, size) ||
        !SHA256_Final(hash, &ctx)) {
        return 0;
    }
    return 1;
}

static int compute_stack_hash(stack_trace_t *trace) {
    if (!trace || trace->depth <= 0) return 0;
    
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx) || 
        !SHA256_Update(&ctx, trace->stack, trace->depth * sizeof(void*)) ||
        !SHA256_Final(trace->hash, &ctx)) {
        return 0;
    }
    return 1;
}

static int get_stack_trace(stack_trace_t *trace) {
    if (!trace) return -1;
    
    trace->depth = backtrace(trace->stack, MAX_STACK_FRAMES);
    if (trace->depth > 0) {
        if (!compute_stack_hash(trace)) {
            return -1;
        }
        return 0;
    }
    return -1;
}

static int verify_region_integrity(protected_region_t *region) {
    if (!region || !region->address || region->size == 0) return 0;
    
    if (memcmp((unsigned char*)region->address - CANARY_SIZE, 
               region->canary_pre, CANARY_SIZE) != 0) {
        return 0;
    }
    
    if (memcmp((unsigned char*)region->address + region->size,
               region->canary_post, CANARY_SIZE) != 0) {
        return 0;
    }
    
    unsigned char current_hash[SHA256_DIGEST_LENGTH];
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    if (!hmac_ctx) return 0;
    
    int result = 0;
    if (HMAC_Init_ex(hmac_ctx, protector.key, sizeof(protector.key), EVP_sha256(), NULL) &&
        HMAC_Update(hmac_ctx, region->address, region->size) &&
        HMAC_Final(hmac_ctx, current_hash, NULL)) {
        result = (memcmp(current_hash, region->hmac, SHA256_DIGEST_LENGTH) == 0);
    }
    
    HMAC_CTX_free(hmac_ctx);
    return result;
}

static void record_telemetry_event(enhanced_protector_t* prot, 
                                 const char* description,
                                 void* context,
                                 int severity) {
    if (!prot || !description) return;
    
    pthread_mutex_lock(&prot->telemetry_lock);
    
    if (prot->telemetry_count < TELEMETRY_BUFFER_SIZE) {
        telemetry_event_t* event = &prot->telemetry_buffer[prot->telemetry_count++];
        
        event->timestamp = time(NULL);
        strncpy(event->description, description, sizeof(event->description) - 1);
        event->description[sizeof(event->description) - 1] = '\0';
        event->severity = severity;
        event->context = context;
        
        if (context) {
            SHA256_CTX sha_ctx;
            if (SHA256_Init(&sha_ctx) && 
                SHA256_Update(&sha_ctx, context, 64) &&
                SHA256_Final(event->evidence_hash, &sha_ctx)) {
            } else {
                memset(event->evidence_hash, 0, SHA256_DIGEST_LENGTH);
            }
        }
    }
    
    pthread_mutex_unlock(&prot->telemetry_lock);
}

static void record_violation(protected_region_t *region, pid_t pid, uid_t uid) {
    if (!region) return;
    
    pthread_mutex_lock(&protector.violation_lock);
    
    violation_record_t *record = NULL;
    for (int i = 0; i < protector.violation_count; i++) {
        if (protector.violations[i].pid == pid) {
            record = &protector.violations[i];
            break;
        }
    }
    
    if (!record && protector.violation_count < MAX_VIOLATIONS) {
        record = &protector.violations[protector.violation_count++];
        record->pid = pid;
        record->uid = uid;
        record->violation_count = 0;
        
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", pid);
        FILE *f = fopen(proc_path, "r");
        if (f) {
            if (fgets(record->comm, sizeof(record->comm), f)) {
                record->comm[strcspn(record->comm, "\n")] = 0;
            }
            fclose(f);
        }
        
        stack_trace_t trace;
        if (get_stack_trace(&trace) == 0) {
            memcpy(record->stack_hash, trace.hash, SHA256_DIGEST_LENGTH);
        }
    }
    
    if (record) {
        record->timestamp = time(NULL);
        record->addr = region->address;
        record->violation_count++;
        
        if (record->violation_count >= VIOLATION_THRESHOLD) {
            kill(pid, SIGKILL);
            record_telemetry_event(&protector, "Process terminated due to violation threshold", 
                                 record, 3);
        }
    }
    
    pthread_mutex_unlock(&protector.violation_lock);
}

static void create_memory_backup(enhanced_protector_t* prot, protected_region_t* region) {
    if (!prot || !region) return;
    
    pthread_mutex_lock(&prot->backup_lock);
    
    for (int i = MAX_BACKUP_COPIES - 1; i > 0; i--) {
        memory_backup_t* curr = &prot->backups[region->index][i];
        memory_backup_t* prev = &prot->backups[region->index][i-1];
        
        if (prev->backup_location) {
            memcpy(curr, prev, sizeof(memory_backup_t));
        }
    }
    
    memory_backup_t* new_backup = &prot->backups[region->index][0];
    new_backup->backup_location = mmap(NULL, region->size, 
                                     PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (new_backup->backup_location != MAP_FAILED) {
        memcpy(new_backup->backup_location, region->address, region->size);
        new_backup->backup_size = region->size;
        new_backup->backup_time = time(NULL);
        
        if (!compute_hash(region->address, region->size, new_backup->original_hash)) {
            memset(new_backup->original_hash, 0, SHA256_DIGEST_LENGTH);
        }
        if (!compute_hash(new_backup->backup_location, region->size, new_backup->backup_hash)) {
            memset(new_backup->backup_hash, 0, SHA256_DIGEST_LENGTH);
        }
    }
    
    pthread_mutex_unlock(&prot->backup_lock);
}

static int verify_and_restore_from_backup(enhanced_protector_t* prot, protected_region_t* region) {
    if (!prot || !region) return 0;
    
    pthread_mutex_lock(&prot->backup_lock);
    
    int restored = 0;
    unsigned char current_hash[SHA256_DIGEST_LENGTH];
    if (!compute_hash(region->address, region->size, current_hash)) {
        pthread_mutex_unlock(&prot->backup_lock);
        return 0;
    }
    
    for (int i = 0; i < MAX_BACKUP_COPIES && !restored; i++) {
        memory_backup_t* backup = &prot->backups[region->index][i];
        
        if (!backup->backup_location) continue;
        
        unsigned char backup_hash[SHA256_DIGEST_LENGTH];
        if (!compute_hash(backup->backup_location, backup->backup_size, backup_hash)) {
            continue;
        }
        
        if (memcmp(backup_hash, backup->backup_hash, SHA256_DIGEST_LENGTH) == 0) {
            if (mprotect(region->address, region->size, PROT_READ | PROT_WRITE) == 0) {
                memcpy(region->address, backup->backup_location, region->size);
                mprotect(region->address, region->size, PROT_READ);
                
                restored = 1;
                
                record_telemetry_event(prot, "Memory restored from backup", 
                                     region->address, 2);
            }
        }
    }
    
    if (!restored) {
        for (int i = MAX_BACKUP_COPIES - 1; i >= 0; i--) {
            memory_backup_t* backup = &prot->backups[region->index][i];
            if (backup->backup_location && backup->backup_location != MAP_FAILED) {
                if (mprotect(region->address, region->size, PROT_READ | PROT_WRITE) == 0) {
                    memcpy(region->address, backup->backup_location, region->size);
                    mprotect(region->address, region->size, PROT_READ);
                    restored = 1;
                    record_telemetry_event(prot, "Memory restored from fallback backup", 
                                         region->address, 2);
                    break;
                }
            }
        }
    }
    
    pthread_mutex_unlock(&prot->backup_lock);
    return restored;
}

static void rotate_encryption_keys(enhanced_protector_t* prot) {
    if (!prot) return;
    
    pthread_mutex_lock(&prot->region_lock);
    
    unsigned char new_key[32];
    if (getrandom(new_key, sizeof(new_key), 0) == sizeof(new_key)) {
        for (int i = 0; i < prot->region_count; i++) {
            protected_region_t* region = &prot->regions[i];
            
            unsigned char* temp = malloc(region->size);
            if (!temp) continue;
            
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                free(temp);
                continue;
            }
            
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, 
                                 prot->runtime_encryption_key, prot->iv)) {
                int outlen;
                if (crypto_operation_safe(ctx, region->address, temp, region->size, 0)) {
                    EVP_CIPHER_CTX_free(ctx);
                    ctx = EVP_CIPHER_CTX_new();
                    
                    if (ctx && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, new_key, prot->iv)) {
                        if (crypto_operation_safe(ctx, temp, region->address, region->size, 1)) {
                            generate_canary(region->canary_pre, CANARY_SIZE);
                            generate_canary(region->canary_post, CANARY_SIZE);
                            
                            HMAC_CTX* hmac_ctx = HMAC_CTX_new();
                            if (hmac_ctx && 
                                HMAC_Init_ex(hmac_ctx, new_key, sizeof(new_key), EVP_sha256(), NULL) &&
                                HMAC_Update(hmac_ctx, region->address, region->size) &&
                                HMAC_Final(hmac_ctx, region->hmac, NULL)) {
                            }
                            HMAC_CTX_free(hmac_ctx);
                        }
                    }
                }
            }
            
            EVP_CIPHER_CTX_free(ctx);
            free(temp);
        }
        
        memcpy(prot->runtime_encryption_key, new_key, sizeof(new_key));
        prot->last_key_rotation = time(NULL);
    }
    
    pthread_mutex_unlock(&prot->region_lock);
}

static int add_trusted_process(enhanced_protector_t* prot, pid_t pid) {
    if (!prot || prot->trusted_process_count >= MAX_TRUSTED_PROCESSES) return -1;
    
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd == -1) return -1;
    
    struct stat fd_st;
    if (fstat(fd, &fd_st) != 0 || st.st_ino != fd_st.st_ino || st.st_dev != fd_st.st_dev) {
        close(fd);
        return -1;
    }
    
    trusted_process_t* proc = &prot->trusted_processes[prot->trusted_process_count];
    
    proc->pid = pid;
    proc->uid = st.st_uid;
    proc->fd = fd;
    proc->inode = st.st_ino;
    proc->device = st.st_dev;
    
    FILE* f = fopen("/proc/%d/comm", pid);
    if (f) {
        if (fgets(proc->comm, sizeof(proc->comm), f)) {
            proc->comm[strcspn(proc->comm, "\n")] = 0;
        }
        fclose(f);
    }
    
    unsigned char buffer[8192];
    ssize_t bytes_read;
    SHA256_CTX ctx;
    
    if (SHA256_Init(&ctx)) {
        lseek(fd, 0, SEEK_SET);
        while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
            SHA256_Update(&ctx, buffer, bytes_read);
        }
        SHA256_Final(proc->binary_hash, &ctx);
    } else {
        memset(proc->binary_hash, 0, SHA256_DIGEST_LENGTH);
    }
    
    proc->last_verified = time(NULL);
    proc->trust_level = 1;
    
    prot->trusted_process_count++;
    return 0;
}

static int verify_trusted_process(enhanced_protector_t* prot, int index) {
    if (!prot || index < 0 || index >= prot->trusted_process_count) return -1;
    
    trusted_process_t* proc = &prot->trusted_processes[index];
    
    struct stat st;
    if (fstat(proc->fd, &st) != 0 || st.st_ino != proc->inode || st.st_dev != proc->device) {
        return 0;
    }
    
    unsigned char current_hash[SHA256_DIGEST_LENGTH];
    unsigned char buffer[8192];
    ssize_t bytes_read;
    SHA256_CTX ctx;
    
    if (SHA256_Init(&ctx)) {
        lseek(proc->fd, 0, SEEK_SET);
        while ((bytes_read = read(proc->fd, buffer, sizeof(buffer))) > 0) {
            SHA256_Update(&ctx, buffer, bytes_read);
        }
        SHA256_Final(current_hash, &ctx);
        
        if (memcmp(current_hash, proc->binary_hash, SHA256_DIGEST_LENGTH) == 0) {
            proc->last_verified = time(NULL);
            return 1;
        }
    }
    
    return 0;
}

static int verify_hook_point(enhanced_protector_t* prot, int hook_index) {
    if (!prot || hook_index >= prot->hook_count) return -1;
    
    hook_point_t* hook = &prot->hooks[hook_index];
    
    if (memcmp(hook->address, hook->original_bytes, hook->hook_size) != 0) {
        memcpy(hook->current_bytes, hook->address, hook->hook_size);
        hook->status = 0;
        
        record_telemetry_event(prot, "Hook point tampering detected",
                             hook->address, 3);
        return 1;
    }
    
    hook->status = 1;
    return 0;
}

static void* netlink_monitor(void* arg) {
    enhanced_protector_t* prot = (enhanced_protector_t*)arg;
    if (!prot) return NULL;
    
    struct sockaddr_nl nl_addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = getpid(),
        .nl_groups = CN_IDX_PROC
    };
    
    if (bind(prot->netlink_socket, (struct sockaddr*)&nl_addr, 
             sizeof(nl_addr)) == -1) {
        return NULL;
    }
    
    char buffer[NETLINK_BUFFER_SIZE];
    
    while (prot->active) {
        ssize_t len = recv(prot->netlink_socket, buffer, sizeof(buffer), 0);
        if (len > 0) {
            struct nlmsghdr* nlh = (struct nlmsghdr*)buffer;
            
            while (NLMSG_OK(nlh, len)) {
                if (nlh->nlmsg_type == NLMSG_DONE) break;
                
                struct cn_msg* cn_msg = NLMSG_DATA(nlh);
                struct proc_event* event = (struct proc_event*)cn_msg->data;
                
                switch (event->what) {
                    case PROC_EVENT_PTRACE:
                        break;
                        
                    case PROC_EVENT_EXEC:
                        break;
                }
                
                nlh = NLMSG_NEXT(nlh, len);
            }
        }
    }
    
    return NULL;
}

static int perform_self_test(enhanced_protector_t* prot) {
    if (!prot) return 0;
    
    prot->self_test_status = 1;
    int test_passed = 1;
    
    void* test_region = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (test_region != MAP_FAILED) {
        memset(test_region, 0xAA, PAGE_SIZE);
        
        if (protect_memory_region(test_region, PAGE_SIZE) == 0) {
            if (mprotect(test_region, PAGE_SIZE, PROT_READ | PROT_WRITE) == 0) {
                ((char*)test_region)[0] = 0xBB;
                
                for (int i = 0; i < prot->violation_count; i++) {
                    if (prot->violations[i].addr == test_region) {
                        test_passed &= 1;
                        break;
                    }
                }
            }
        }
        
        munmap(test_region, PAGE_SIZE);
    }
    
    unsigned char test_data[64];
    if (getrandom(test_data, sizeof(test_data), 0) != sizeof(test_data)) {
        test_passed = 0;
    } else {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx) {
            unsigned char encrypted[128], decrypted[128];
            int outlen;
            
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
                                  prot->runtime_encryption_key, prot->iv) &&
                crypto_operation_safe(ctx, test_data, encrypted, sizeof(test_data), 1)) {
                
                EVP_CIPHER_CTX_free(ctx);
                ctx = EVP_CIPHER_CTX_new();
                
                if (ctx && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
                                      prot->runtime_encryption_key, prot->iv) &&
                    crypto_operation_safe(ctx, encrypted, decrypted, sizeof(test_data), 0)) {
                    
                    test_passed &= (memcmp(test_data, decrypted, sizeof(test_data)) == 0);
                } else {
                    test_passed = 0;
                }
            } else {
                test_passed = 0;
            }
            
            EVP_CIPHER_CTX_free(ctx);
        } else {
            test_passed = 0;
        }
    }
    
    unsigned char current_hash[SHA256_DIGEST_LENGTH];
    FILE* f = fopen(prot->edr_binary_path, "rb");
    if (f) {
        SHA256_CTX sha_ctx;
        if (SHA256_Init(&sha_ctx)) {
            char buf[8192];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
                SHA256_Update(&sha_ctx, buf, n);
            }
            if (SHA256_Final(current_hash, &sha_ctx)) {
                test_passed &= (memcmp(current_hash, prot->edr_binary_hash,
                                      SHA256_DIGEST_LENGTH) == 0);
            } else {
                test_passed = 0;
            }
        } else {
            test_passed = 0;
        }
        fclose(f);
    } else {
        test_passed = 0;
    }
    
    for (int i = 0; i < prot->trusted_process_count; i++) {
        if (verify_trusted_process(prot, i) != 1) {
            test_passed = 0;
            break;
        }
    }
    
    prot->last_self_test = time(NULL);
    prot->self_test_status = test_passed;
    
    return test_passed;
}

static void adaptive_check_interval(enhanced_protector_t* prot, uint64_t scan_time_ns) {
    if (!prot) return;
    
    prot->total_scan_time_ns += scan_time_ns;
    prot->scan_count++;
    
    uint64_t avg_scan_time = prot->total_scan_time_ns / prot->scan_count;
    
    if (avg_scan_time > 10000000) {
        prot->current_check_interval += ADAPTIVE_CHECK_INTERVAL_STEP;
        if (prot->current_check_interval > MAX_CHECK_INTERVAL_MS) {
            prot->current_check_interval = MAX_CHECK_INTERVAL_MS;
        }
    } else if (avg_scan_time < 5000000) {
        prot->current_check_interval -= ADAPTIVE_CHECK_INTERVAL_STEP;
        if (prot->current_check_interval < MIN_CHECK_INTERVAL_MS) {
            prot->current_check_interval = MIN_CHECK_INTERVAL_MS;
        }
    }
    
    if (prot->scan_count % 100 == 0) {
        prot->total_scan_time_ns = 0;
        prot->scan_count = 0;
    }
}

static void *monitor_thread(void *arg) {
    enhanced_protector_t* prot = (enhanced_protector_t*)arg;
    if (!prot) return NULL;
    
    struct pollfd fds[2];
    fds[0].fd = prot->timer_fd;
    fds[0].events = POLLIN;
    fds[1].fd = prot->event_fd;
    fds[1].events = POLLIN;
    
    struct itimerspec its;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = prot->current_check_interval * 1000000;
    its.it_value = its.it_interval;
    
    if (timerfd_settime(prot->timer_fd, 0, &its, NULL) == -1) {
        return NULL;
    }
    
    while (prot->active) {
        int ret = poll(fds, 2, -1);
        if (ret <= 0) continue;
        
        if (fds[0].revents & POLLIN) {
            uint64_t expirations;
            read(prot->timer_fd, &expirations, sizeof(expirations));
            
            struct timespec start, end;
            clock_gettime(CLOCK_MONOTONIC, &start);
            
            pthread_mutex_lock(&prot->region_lock);
            for (int i = 0; i < prot->region_count; i++) {
                if (!verify_region_integrity(&prot->regions[i])) {
                    if (!verify_and_restore_from_backup(prot, &prot->regions[i])) {
                        record_violation(&prot->regions[i], getpid(), geteuid());
                        create_memory_backup(prot, &prot->regions[i]);
                    }
                }
                prot->regions[i].check_count++;
            }
            pthread_mutex_unlock(&prot->region_lock);
            
            clock_gettime(CLOCK_MONOTONIC, &end);
            uint64_t scan_time_ns = (end.tv_sec - start.tv_sec) * 1000000000 + 
                                   (end.tv_nsec - start.tv_nsec);
            
            adaptive_check_interval(prot, scan_time_ns);
            
            its.it_interval.tv_nsec = prot->current_check_interval * 1000000;
            its.it_value = its.it_interval;
            timerfd_settime(prot->timer_fd, 0, &its, NULL);
            
            prot->integrity_checks++;
            if (prot->integrity_checks % 1000 == 0) {
                update_entropy();
            }
            
            if (time(NULL) - prot->last_key_rotation > THREAT_INTELLIGENCE_UPDATE_INTERVAL) {
                rotate_encryption_keys(prot);
            }
        }
        
        if (fds[1].revents & POLLIN) {
            uint64_t val;
            read(prot->event_fd, &val, sizeof(val));
        }
    }
    
    return NULL;
}

static int is_monitor_thread_healthy(enhanced_protector_t* prot) {
    if (!prot) return 0;
    
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    
    if ((now.tv_sec - prot->last_check.tv_sec) > 2) {
        int healthy = 0;
        
        pthread_mutex_lock(&prot->region_lock);
        if (prot->region_count > 0) {
            protected_region_t* region = &prot->regions[0];
            healthy = verify_region_integrity(region);
        }
        pthread_mutex_unlock(&prot->region_lock);
        
        return healthy;
    }
    
    return 1;
}

static void *watchdog_thread(void *arg) {
    enhanced_protector_t* prot = (enhanced_protector_t*)arg;
    if (!prot) return NULL;
    
    while (prot->active) {
        if (!is_monitor_thread_healthy(prot)) {
            record_telemetry_event(prot, "Monitor thread unhealthy, performing recovery", NULL, 2);
            
            pthread_cancel(prot->monitor_thread);
            pthread_create(&prot->monitor_thread, NULL, monitor_thread, prot);
            
            perform_self_test(prot);
        }
        
        usleep(WATCHDOG_INTERVAL_MS * 1000);
    }
    return NULL;
}

int init_enhanced_protection(const char* edr_path) {
    memset(&protector, 0, sizeof(enhanced_protector_t));
    
    if (pthread_mutex_init(&protector.region_lock, NULL) != 0 ||
        pthread_mutex_init(&protector.violation_lock, NULL) != 0 ||
        pthread_mutex_init(&protector.backup_lock, NULL) != 0 ||
        pthread_mutex_init(&protector.telemetry_lock, NULL) != 0 ||
        pthread_rwlock_init(&protector.region_rwlock, NULL) != 0) {
        return -1;
    }
    
    protector.telemetry_buffer = calloc(TELEMETRY_BUFFER_SIZE, sizeof(telemetry_event_t));
    if (!protector.telemetry_buffer) return -1;
    
    ssize_t key_read = getrandom(protector.key, sizeof(protector.key), 0);
    ssize_t iv_read = getrandom(protector.iv, sizeof(protector.iv), 0);
    ssize_t enc_key_read = getrandom(protector.runtime_encryption_key, 32, 0);
    
    if (key_read != sizeof(protector.key) || 
        iv_read != sizeof(protector.iv) || 
        enc_key_read != 32) {
        free(protector.telemetry_buffer);
        return -1;
    }
    
    update_entropy();
    
    protector.cipher_ctx = EVP_CIPHER_CTX_new();
    if (!protector.cipher_ctx) {
        free(protector.telemetry_buffer);
        return -1;
    }
    
    protector.event_fd = eventfd(0, EFD_NONBLOCK);
    protector.timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    protector.inotify_fd = inotify_init1(IN_NONBLOCK);
    protector.netlink_socket = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    
    if (protector.event_fd == -1 || protector.timer_fd == -1 || 
        protector.inotify_fd == -1 || protector.netlink_socket == -1) {
        free(protector.telemetry_buffer);
        EVP_CIPHER_CTX_free(protector.cipher_ctx);
        return -1;
    }
    
    protector.current_check_interval = MEMORY_SCAN_INTERVAL_MS;
    
    strncpy(protector.edr_binary_path, edr_path, PATH_MAX - 1);
    protector.edr_binary_path[PATH_MAX - 1] = '\0';
    
    FILE* f = fopen(edr_path, "rb");
    if (f) {
        SHA256_CTX ctx;
        if (SHA256_Init(&ctx)) {
            char buf[8192];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
                SHA256_Update(&ctx, buf, n);
            }
            if (!SHA256_Final(protector.edr_binary_hash, &ctx)) {
                memset(protector.edr_binary_hash, 0, SHA256_DIGEST_LENGTH);
            }
        } else {
            memset(protector.edr_binary_hash, 0, SHA256_DIGEST_LENGTH);
        }
        fclose(f);
    } else {
        memset(protector.edr_binary_hash, 0, SHA256_DIGEST_LENGTH);
    }
    
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_PAGE_FAULTS;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    
    protector.perf_fds[0] = perf_event_open(&attr, 0, -1, -1, 0);
    if (protector.perf_fds[0] >= 0) {
        ioctl(protector.perf_fds[0], PERF_EVENT_IOC_RESET, 0);
        ioctl(protector.perf_fds[0], PERF_EVENT_IOC_ENABLE, 0);
    }
    
    protector.active = 1;
    
    if (pthread_create(&protector.monitor_thread, NULL, monitor_thread, &protector) != 0) {
        cleanup_memory_protection();
        return -1;
    }
    
    if (pthread_create(&protector.watchdog_thread, NULL, watchdog_thread, &protector) != 0) {
        cleanup_memory_protection();
        return -1;
    }
    
    if (pthread_create(&protector.netlink_thread, NULL, netlink_monitor, &protector) != 0) {
        cleanup_memory_protection();
        return -1;
    }
    
    if (!perform_self_test(&protector)) {
        cleanup_memory_protection();
        return -1;
    }
    
    return 0;
}

int protect_memory_region(void *address, size_t size) {
    if (!address || !size || !protector.active) {
        return -1;
    }
    
    pthread_mutex_lock(&protector.region_lock);
    
    if (protector.region_count >= MAX_PROTECTED_REGIONS) {
        pthread_mutex_unlock(&protector.region_lock);
        return -1;
    }
    
    protected_region_t *region = &protector.regions[protector.region_count];
    
    void *aligned_addr = (void*)((uintptr_t)address & ~(PAGE_SIZE - 1));
    size_t aligned_size = (size + ((uintptr_t)address - (uintptr_t)aligned_addr) + 
                          PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    
    if (mprotect(aligned_addr, aligned_size, PROT_READ) != 0) {
        pthread_mutex_unlock(&protector.region_lock);
        return -1;
    }
    
    generate_canary(region->canary_pre, CANARY_SIZE);
    generate_canary(region->canary_post, CANARY_SIZE);
    
    memcpy((unsigned char*)address - CANARY_SIZE, region->canary_pre, CANARY_SIZE);
    memcpy((unsigned char*)address + size, region->canary_post, CANARY_SIZE);
    
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    if (!hmac_ctx) {
        pthread_mutex_unlock(&protector.region_lock);
        return -1;
    }
    
    int success = 0;
    if (HMAC_Init_ex(hmac_ctx, protector.key, sizeof(protector.key), EVP_sha256(), NULL) &&
        HMAC_Update(hmac_ctx, address, size) &&
        HMAC_Final(hmac_ctx, region->hmac, NULL)) {
        success = 1;
    }
    
    HMAC_CTX_free(hmac_ctx);
    
    if (!success) {
        pthread_mutex_unlock(&protector.region_lock);
        return -1;
    }
    
    region->address = address;
    region->size = size;
    region->check_count = 0;
    region->last_check = time(NULL);
    region->index = protector.region_count;
    
    create_memory_backup(&protector, region);
    
    protector.region_count++;
    
    pthread_mutex_unlock(&protector.region_lock);
    return 0;
}

void cleanup_memory_protection(void) {
    if (!protector.active) return;
    
    protector.active = 0;
    
    uint64_t val = 1;
    write(protector.event_fd, &val, sizeof(val));
    
    pthread_join(protector.monitor_thread, NULL);
    pthread_join(protector.watchdog_thread, NULL);
    pthread_join(protector.netlink_thread, NULL);
    
    pthread_mutex_lock(&protector.region_lock);
    for (int i = 0; i < protector.region_count; i++) {
        protected_region_t *region = &protector.regions[i];
        void *aligned_addr = (void*)((uintptr_t)region->address & ~(PAGE_SIZE - 1));
        size_t aligned_size = (region->size + ((uintptr_t)region->address - 
                             (uintptr_t)aligned_addr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        mprotect(aligned_addr, aligned_size, PROT_READ | PROT_WRITE);
    }
    pthread_mutex_unlock(&protector.region_lock);
    
    for (int i = 0; i < protector.trusted_process_count; i++) {
        if (protector.trusted_processes[i].fd != -1) {
            close(protector.trusted_processes[i].fd);
        }
    }
    
    close(protector.event_fd);
    close(protector.timer_fd);
    close(protector.inotify_fd);
    close(protector.netlink_socket);
    
    for (int i = 0; i < 8; i++) {
        if (protector.perf_fds[i] >= 0) {
            close(protector.perf_fds[i]);
        }
    }
    
    EVP_CIPHER_CTX_free(protector.cipher_ctx);
    
    pthread_mutex_destroy(&protector.region_lock);
    pthread_mutex_destroy(&protector.violation_lock);
    pthread_mutex_destroy(&protector.backup_lock);
    pthread_mutex_destroy(&protector.telemetry_lock);
    pthread_rwlock_destroy(&protector.region_rwlock);
    
    free(protector.telemetry_buffer);
    
    explicit_bzero(&protector, sizeof(protector));
}