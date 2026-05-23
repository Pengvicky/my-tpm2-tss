#ifndef FILE_UTIL_H
#define FILE_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int read_binary_file(const char *path, uint8_t **data, size_t *len);
int write_binary_file(const char *path, const uint8_t *data, size_t len);
int read_message_input(const char *message_text, const char *message_file,
    uint8_t **data, size_t *len);
int parse_u32(const char *text, uint32_t *value);
void print_hex(FILE *stream, const uint8_t *data, size_t len);

#endif