#ifndef COMPRESS_H
#define COMPRESS_H

#include <stdint.h>
#include <stddef.h>

#define COMPRESS_ALGO_LZMA 1
#define COMPRESS_ALGO_ZSTD 2
#define COMPRESS_ALGO_DEFLATE 3

typedef struct {
    int algorithm;
    int compression_level;
    int thread_count;
    size_t buffer_size;
    size_t block_size;
} compress_config_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint8_t algorithm;
    uint8_t reserved[7];
    uint64_t original_size;
    uint64_t compressed_size;
    uint32_t crc;
    uint32_t block_size;
} compress_header_t;

int compress_init(compress_config_t *config);
int compress_file(const char *input_path, const char *output_path, compress_config_t *config);
int decompress_file(const char *input_path, const char *output_path);
int compress_directory(const char *input_dir, const char *output_path, compress_config_t *config);
int decompress_directory(const char *input_path, const char *output_dir);
int compress_auto(const char *input_path, const char *output_path, compress_config_t *config);
int decompress_auto(const char *input_path, const char *output_path);
int compress_buffer(const uint8_t *input, size_t input_size, uint8_t *output, size_t *output_size, compress_config_t *config);
int decompress_buffer(uint8_t algorithm, const uint8_t *input, size_t input_size, uint8_t *output, size_t *output_size);
const char *compress_error_string(int error_code);

#endif