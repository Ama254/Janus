#include "compress.h"
#include <lzma.h>
#include <zstd.h>
#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#define DEFAULT_BUFFER_SIZE 65536
#define MAX_BUFFER_SIZE (1024UL * 1024UL * 64UL)
#define MAX_THREADS 16
#define COMPRESS_MAGIC 0x43504D50
#define COMPRESS_VERSION 1

static int safe_write(FILE *f, const void *buf, size_t size)
{
    size_t wrote = fwrite(buf, 1, size, f);
    return (wrote == size) ? 0 : -EIO;
}

static int write_le32(FILE *f, uint32_t v)
{
    uint8_t b[4];
    b[0] = v & 0xFF;
    b[1] = (v >> 8) & 0xFF;
    b[2] = (v >> 16) & 0xFF;
    b[3] = (v >> 24) & 0xFF;
    return safe_write(f, b, 4);
}

static int write_le64(FILE *f, uint64_t v)
{
    uint8_t b[8];
    for (int i = 0; i < 8; ++i) b[i] = (v >> (i * 8)) & 0xFF;
    return safe_write(f, b, 8);
}

static int read_le32(FILE *f, uint32_t *out)
{
    uint8_t b[4];
    if (fread(b, 1, 4, f) != 4) return -EIO;
    *out = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    return 0;
}

static int read_le64(FILE *f, uint64_t *out)
{
    uint8_t b[8];
    if (fread(b, 1, 8, f) != 8) return -EIO;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= ((uint64_t)b[i]) << (i * 8);
    *out = v;
    return 0;
}

int compress_init(compress_config_t *config)
{
    if (!config) return -EINVAL;
    if (config->compression_level < 1 || config->compression_level > 22) config->compression_level = 6;
    if (config->thread_count < 1 || config->thread_count > MAX_THREADS) config->thread_count = 1;
    if (config->buffer_size == 0) config->buffer_size = DEFAULT_BUFFER_SIZE;
    if (config->buffer_size > MAX_BUFFER_SIZE) config->buffer_size = MAX_BUFFER_SIZE;
    if (config->block_size < config->buffer_size) config->block_size = config->buffer_size;
    return 0;
}

int compress_buffer(const uint8_t *input, size_t input_size, uint8_t *output, size_t *output_size, compress_config_t *config)
{
    if (!input || !output || !output_size || !config) return -EINVAL;
    switch (config->algorithm) {
    case COMPRESS_ALGO_LZMA: {
        lzma_stream strm = LZMA_STREAM_INIT;
        lzma_ret ret = lzma_easy_encoder(&strm, config->compression_level, LZMA_CHECK_CRC64);
        if (ret != LZMA_OK) return -1;
        strm.next_in = input;
        strm.avail_in = input_size;
        strm.next_out = output;
        strm.avail_out = *output_size;
        ret = lzma_code(&strm, LZMA_FINISH);
        *output_size = (size_t)strm.total_out;
        lzma_end(&strm);
        return (ret == LZMA_STREAM_END) ? 0 : -1;
    }
    case COMPRESS_ALGO_ZSTD: {
        size_t bound = ZSTD_compressBound(input_size);
        if (*output_size < bound) return -ENOMEM;
        size_t result = ZSTD_compress(output, *output_size, input, input_size, config->compression_level);
        if (ZSTD_isError(result)) return -1;
        *output_size = result;
        return 0;
    }
    case COMPRESS_ALGO_DEFLATE: {
        z_stream strm;
        memset(&strm, 0, sizeof(strm));
        int init_ret = deflateInit(&strm, config->compression_level);
        if (init_ret != Z_OK) return -1;
        strm.next_in = (Bytef*)input;
        strm.avail_in = (uInt)input_size;
        strm.next_out = output;
        strm.avail_out = (uInt)*output_size;
        int ret = deflate(&strm, Z_FINISH);
        *output_size = strm.total_out;
        deflateEnd(&strm);
        return (ret == Z_STREAM_END) ? 0 : -1;
    }
    default:
        return -EINVAL;
    }
}

int compress_file(const char *input_path, const char *output_path, compress_config_t *config)
{
    if (!input_path || !output_path || !config) return -EINVAL;
    FILE *in_file = NULL;
    FILE *out_file = NULL;
    char tmp_path[PATH_MAX];
    uint8_t *in_buf = NULL;
    uint8_t *out_buf = NULL;
    int result = 0;
    in_file = fopen(input_path, "rb");
    if (!in_file) return -errno;
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", output_path);
    out_file = fopen(tmp_path, "wb");
    if (!out_file) { result = -errno; goto cleanup; }
    compress_header_t header;
    memset(&header, 0, sizeof(header));
    header.magic = COMPRESS_MAGIC;
    header.version = COMPRESS_VERSION;
    header.algorithm = (uint8_t)config->algorithm;
    header.block_size = (uint32_t)config->block_size;
    if (fseeko(in_file, 0, SEEK_END) != 0) { result = -EIO; goto cleanup; }
    off_t orig_off = ftello(in_file);
    if (orig_off < 0) orig_off = 0;
    header.original_size = (uint64_t)orig_off;
    if (fseeko(in_file, 0, SEEK_SET) != 0) { result = -EIO; goto cleanup; }
    if (safe_write(out_file, &header, sizeof(header)) != 0) { result = -EIO; goto cleanup; }
    in_buf = malloc(config->block_size);
    if (!in_buf) { result = -ENOMEM; goto cleanup; }
    size_t out_capacity = config->block_size + 65536 + 1;
    out_buf = malloc(out_capacity);
    if (!out_buf) { result = -ENOMEM; goto cleanup; }
    uint64_t total_read = 0;
    uint32_t crc = crc32(0L, Z_NULL, 0);
    while (1) {
        size_t read_size = fread(in_buf, 1, config->block_size, in_file);
        if (read_size == 0) {
            if (feof(in_file)) break;
            result = -EIO; goto cleanup;
        }
        crc = crc32(crc, in_buf, (uInt)read_size);
        size_t avail_out = out_capacity - 1;
        size_t compressed_size = avail_out;
        if (config->algorithm == COMPRESS_ALGO_ZSTD) {
            size_t bound = ZSTD_compressBound(read_size);
            if (bound > avail_out) {
                uint8_t *tmp = realloc(out_buf, bound + 1);
                if (!tmp) { result = -ENOMEM; goto cleanup; }
                out_buf = tmp;
                out_capacity = bound + 1;
                avail_out = out_capacity - 1;
                compressed_size = avail_out;
            }
        }
        int rc = compress_buffer(in_buf, read_size, out_buf + 1, &compressed_size, config);
        if (rc < 0) { result = rc; goto cleanup; }
        out_buf[0] = (uint8_t)config->algorithm;
        uint32_t block_len = (uint32_t)(compressed_size + 1);
        if (write_le32(out_file, block_len) != 0) { result = -EIO; goto cleanup; }
        if (safe_write(out_file, out_buf, block_len) != 0) { result = -EIO; goto cleanup; }
        total_read += read_size;
    }
    header.crc = crc;
    if (fflush(out_file) != 0) { result = -EIO; goto cleanup; }
    off_t compressed_end = ftello(out_file);
    if (compressed_end < (off_t)sizeof(header)) compressed_end = sizeof(header);
    header.compressed_size = (uint64_t)(compressed_end - sizeof(header));
    if (fseeko(out_file, 0, SEEK_SET) != 0) { result = -EIO; goto cleanup; }
    if (safe_write(out_file, &header, sizeof(header)) != 0) { result = -EIO; goto cleanup; }
    if (fclose(in_file) != 0) { in_file = NULL; }
    if (fclose(out_file) != 0) { out_file = NULL; }
    if (rename(tmp_path, output_path) != 0) { result = -errno; goto cleanup; }
    result = 0;
cleanup:
    if (in_file) fclose(in_file);
    if (out_file) { fclose(out_file); unlink(tmp_path); }
    free(in_buf);
    free(out_buf);
    return result;
}

static int ensure_parent_dirs(const char *path)
{
    char tmp[PATH_MAX];
    strncpy(tmp, path, PATH_MAX - 1);
    tmp[PATH_MAX - 1] = '\0';
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return 0;
}

int compress_directory(const char *input_dir, const char *output_path, compress_config_t *config)
{
    if (!input_dir || !output_path || !config) return -EINVAL;
    char tmp_archive[PATH_MAX];
    snprintf(tmp_archive, sizeof(tmp_archive), "%s.archive.tmp", output_path);
    FILE *arc = fopen(tmp_archive, "wb");
    if (!arc) return -errno;
    size_t buf_size = config->buffer_size;
    uint8_t *buf = malloc(buf_size);
    if (!buf) { fclose(arc); unlink(tmp_archive); return -ENOMEM; }
    DIR *d = opendir(input_dir);
    if (!d) { free(buf); fclose(arc); unlink(tmp_archive); return -errno; }
    struct dirent *entry;
    struct stat st;
    char path[PATH_MAX];
    char rel[PATH_MAX];
    size_t base_len = strlen(input_dir);
    if (input_dir[base_len - 1] == '/') base_len--;
    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        snprintf(path, sizeof(path), "%s/%s", input_dir, entry->d_name);
        if (lstat(path, &st) != 0) { closedir(d); free(buf); fclose(arc); unlink(tmp_archive); return -errno; }
        if (S_ISDIR(st.st_mode)) {
            uint8_t type = 2;
            const char *relpath = path + (base_len + 1);
            uint32_t plen = (uint32_t)strlen(relpath);
            if (write_le32(arc, plen) != 0) { closedir(d); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
            if (safe_write(arc, relpath, plen) != 0) { closedir(d); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
            if (write_le64(arc, 0) != 0) { closedir(d); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
            if (safe_write(arc, &type, 1) != 0) { closedir(d); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
            continue;
        }
        if (S_ISREG(st.st_mode)) {
            FILE *f = fopen(path, "rb");
            if (!f) { closedir(d); free(buf); fclose(arc); unlink(tmp_archive); return -errno; }
            const char *relpath = path + (base_len + 1);
            uint32_t plen = (uint32_t)strlen(relpath);
            if (write_le32(arc, plen) != 0) { fclose(f); closedir(d); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
            if (safe_write(arc, relpath, plen) != 0) { fclose(f); closedir(d); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
            if (write_le64(arc, (uint64_t)st.st_size) != 0) { fclose(f); closedir(d); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
            uint8_t type = 1;
            if (safe_write(arc, &type, 1) != 0) { fclose(f); closedir(d); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
            size_t n;
            while ((n = fread(buf, 1, buf_size, f)) > 0) {
                if (safe_write(arc, buf, n) != 0) { fclose(f); closedir(d); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
            }
            fclose(f);
            continue;
        }
    }
    closedir(d);
    free(buf);
    fclose(arc);
    int rc = compress_file(tmp_archive, output_path, config);
    unlink(tmp_archive);
    return rc;
}

int decompress_directory(const char *input_path, const char *output_dir)
{
    if (!input_path || !output_dir) return -EINVAL;
    char tmp_archive[PATH_MAX];
    snprintf(tmp_archive, sizeof(tmp_archive), "%s.archive.tmp", input_path);
    int rc = decompress_file(input_path, tmp_archive);
    if (rc < 0) { unlink(tmp_archive); return rc; }
    FILE *arc = fopen(tmp_archive, "rb");
    if (!arc) { unlink(tmp_archive); return -errno; }
    uint8_t *buf = malloc(DEFAULT_BUFFER_SIZE);
    if (!buf) { fclose(arc); unlink(tmp_archive); return -ENOMEM; }
    while (1) {
        uint32_t plen;
        int r = read_le32(arc, &plen);
        if (r != 0) break;
        char *relpath = malloc(plen + 1);
        if (!relpath) { free(buf); fclose(arc); unlink(tmp_archive); return -ENOMEM; }
        if (fread(relpath, 1, plen, arc) != plen) { free(relpath); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
        relpath[plen] = '\0';
        uint64_t size;
        if (read_le64(arc, &size) != 0) { free(relpath); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
        uint8_t type;
        if (fread(&type, 1, 1, arc) != 1) { free(relpath); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
        char outpath[PATH_MAX];
        snprintf(outpath, sizeof(outpath), "%s/%s", output_dir, relpath);
        if (type == 2) {
            ensure_parent_dirs(outpath);
            mkdir(outpath, 0755);
            free(relpath);
            continue;
        }
        ensure_parent_dirs(outpath);
        FILE *f = fopen(outpath, "wb");
        if (!f) { free(relpath); free(buf); fclose(arc); unlink(tmp_archive); return -errno; }
        uint64_t remaining = size;
        while (remaining > 0) {
            size_t toread = (remaining > DEFAULT_BUFFER_SIZE) ? DEFAULT_BUFFER_SIZE : (size_t)remaining;
            size_t got = fread(buf, 1, toread, arc);
            if (got != toread) { fclose(f); free(relpath); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
            if (fwrite(buf, 1, got, f) != got) { fclose(f); free(relpath); free(buf); fclose(arc); unlink(tmp_archive); return -EIO; }
            remaining -= got;
        }
        fclose(f);
        free(relpath);
    }
    free(buf);
    fclose(arc);
    unlink(tmp_archive);
    return 0;
}

int decompress_file(const char *input_path, const char *output_path)
{
    if (!input_path || !output_path) return -EINVAL;
    FILE *in_file = NULL;
    FILE *out_file = NULL;
    uint8_t *in_buf = NULL;
    uint8_t *out_buf = NULL;
    int result = 0;
    in_file = fopen(input_path, "rb");
    if (!in_file) return -errno;
    compress_header_t header;
    if (fread(&header, sizeof(header), 1, in_file) != 1) { result = -EIO; goto cleanup; }
    if (header.magic != COMPRESS_MAGIC || header.version != COMPRESS_VERSION) { result = -EINVAL; goto cleanup; }
    out_file = fopen(output_path, "wb");
    if (!out_file) { result = -errno; goto cleanup; }
    size_t in_cap = header.block_size + 65536;
    in_buf = malloc(in_cap);
    if (!in_buf) { result = -ENOMEM; goto cleanup; }
    out_buf = malloc(header.block_size + 65536);
    if (!out_buf) { result = -ENOMEM; goto cleanup; }
    uint64_t bytes_processed = 0;
    uint32_t crc = crc32(0L, Z_NULL, 0);
    while (bytes_processed < header.compressed_size) {
        uint32_t block_len;
        if (read_le32(in_file, &block_len) != 0) { result = -EIO; goto cleanup; }
        bytes_processed += 4;
        if (block_len == 0) { result = -EINVAL; goto cleanup; }
        if (block_len > in_cap) {
            uint8_t *tmp = realloc(in_buf, block_len);
            if (!tmp) { result = -ENOMEM; goto cleanup; }
            in_buf = tmp;
            in_cap = block_len;
        }
        if (fread(in_buf, 1, block_len, in_file) != block_len) { result = -EIO; goto cleanup; }
        bytes_processed += block_len;
        uint8_t algorithm = in_buf[0];
        size_t comp_size = block_len - 1;
        size_t out_size = header.block_size;
        int rc = decompress_buffer(algorithm, in_buf + 1, comp_size, out_buf, &out_size);
        if (rc < 0) { result = rc; goto cleanup; }
        if (fwrite(out_buf, 1, out_size, out_file) != out_size) { result = -EIO; goto cleanup; }
        crc = crc32(crc, out_buf, (uInt)out_size);
    }
    if (crc != header.crc) { result = -EIO; goto cleanup; }
    result = 0;
cleanup:
    if (in_file) fclose(in_file);
    if (out_file) { fclose(out_file); if (result < 0) unlink(output_path); }
    free(in_buf);
    free(out_buf);
    return result;
}

int compress_auto(const char *input_path, const char *output_path, compress_config_t *config)
{
    struct stat st;
    if (lstat(input_path, &st) != 0) return -errno;
    if (S_ISDIR(st.st_mode)) return compress_directory(input_path, output_path, config);
    if (S_ISREG(st.st_mode)) return compress_file(input_path, output_path, config);
    return -EINVAL;
}

int decompress_auto(const char *input_path, const char *output_path)
{
    struct stat st;
    if (lstat(input_path, &st) == 0 && S_ISDIR(st.st_mode)) return -EINVAL;
    FILE *f = fopen(input_path, "rb");
    if (!f) return -errno;
    compress_header_t header;
    int r = fread(&header, sizeof(header), 1, f) == 1 ? 0 : -EIO;
    fclose(f);
    if (r != 0) return r;
    if (header.magic == COMPRESS_MAGIC && header.version == COMPRESS_VERSION) return decompress_file(input_path, output_path);
    return -EINVAL;
}

int decompress_buffer(uint8_t algorithm, const uint8_t *input, size_t input_size, uint8_t *output, size_t *output_size)
{
    if (!input || !output || !output_size) return -EINVAL;
    switch (algorithm) {
    case COMPRESS_ALGO_LZMA: {
        lzma_stream strm = LZMA_STREAM_INIT;
        lzma_ret ret = lzma_auto_decoder(&strm, UINT64_MAX, 0);
        if (ret != LZMA_OK) return -1;
        strm.next_in = input;
        strm.avail_in = input_size;
        strm.next_out = output;
        strm.avail_out = *output_size;
        ret = lzma_code(&strm, LZMA_FINISH);
        *output_size = (size_t)strm.total_out;
        lzma_end(&strm);
        return (ret == LZMA_STREAM_END) ? 0 : -1;
    }
    case COMPRESS_ALGO_ZSTD: {
        size_t result = ZSTD_decompress(output, *output_size, input, input_size);
        if (ZSTD_isError(result)) return -1;
        *output_size = result;
        return 0;
    }
    case COMPRESS_ALGO_DEFLATE: {
        z_stream strm;
        memset(&strm, 0, sizeof(strm));
        int init_ret = inflateInit(&strm);
        if (init_ret != Z_OK) return -1;
        strm.next_in = (Bytef*)input;
        strm.avail_in = (uInt)input_size;
        strm.next_out = output;
        strm.avail_out = (uInt)*output_size;
        int ret = inflate(&strm, Z_FINISH);
        *output_size = strm.total_out;
        inflateEnd(&strm);
        return (ret == Z_STREAM_END) ? 0 : -1;
    }
    default:
        return -EINVAL;
    }
}

const char *compress_error_string(int error_code)
{
    switch (error_code) {
    case 0: return "Success";
    case -EINVAL: return "Invalid argument";
    case -ENOMEM: return "Out of memory";
    case -EIO: return "I/O error";
    default: return "Unknown error";
    }
}