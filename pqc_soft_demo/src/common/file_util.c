#include "file_util.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int dup_buffer(const uint8_t *src, size_t len, uint8_t **out)
{
    uint8_t *copy;

    copy = malloc(len == 0 ? 1 : len);
    if (copy == NULL) {
        return -1;
    }
    if (len != 0) {
        memcpy(copy, src, len);
    }
    *out = copy;
    return 0;
}

int read_binary_file(const char *path, uint8_t **data, size_t *len)
{
    FILE *file;
    long file_size;
    uint8_t *buffer;
    size_t read_len;

    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "failed to seek %s\n", path);
        fclose(file);
        return -1;
    }
    file_size = ftell(file);
    if (file_size < 0) {
        fprintf(stderr, "failed to size %s\n", path);
        fclose(file);
        return -1;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "failed to rewind %s\n", path);
        fclose(file);
        return -1;
    }

    buffer = malloc(file_size == 0 ? 1 : (size_t)file_size);
    if (buffer == NULL) {
        fprintf(stderr, "failed to allocate %ld bytes for %s\n", file_size, path);
        fclose(file);
        return -1;
    }

    read_len = fread(buffer, 1, (size_t)file_size, file);
    fclose(file);
    if (read_len != (size_t)file_size) {
        fprintf(stderr, "failed to read %s\n", path);
        free(buffer);
        return -1;
    }

    *data = buffer;
    *len = read_len;
    return 0;
}

int write_binary_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *file;
    size_t write_len;

    file = fopen(path, "wb");
    if (file == NULL) {
        fprintf(stderr, "failed to open %s for write: %s\n", path, strerror(errno));
        return -1;
    }

    write_len = fwrite(data, 1, len, file);
    fclose(file);
    if (write_len != len) {
        fprintf(stderr, "failed to write %s\n", path);
        return -1;
    }
    return 0;
}

int read_message_input(const char *message_text, const char *message_file,
    uint8_t **data, size_t *len)
{
    if ((message_text == NULL && message_file == NULL) ||
        (message_text != NULL && message_file != NULL)) {
        fprintf(stderr, "exactly one of --message or --message-file is required\n");
        return -1;
    }

    if (message_text != NULL) {
        *len = strlen(message_text);
        return dup_buffer((const uint8_t *)message_text, *len, data);
    }

    return read_binary_file(message_file, data, len);
}

int parse_u32(const char *text, uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (text == NULL || *text == '\0') {
        return -1;
    }

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == NULL || *end != '\0' || parsed > 0xffffffffUL) {
        return -1;
    }

    *value = (uint32_t)parsed;
    return 0;
}

void print_hex(FILE *stream, const uint8_t *data, size_t len)
{
    size_t index;

    for (index = 0; index < len; ++index) {
        fprintf(stream, "%02x", data[index]);
    }
    fputc('\n', stream);
}