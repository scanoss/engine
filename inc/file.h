#ifndef __FILE_H
    #define __FILE_H

#include <stdint.h>
#include <stdbool.h>

uint64_t get_file_size(char *path);
void read_file(char *out, char *path, uint64_t maxlen);
bool is_file(char *path);
bool is_dir(char *path);
void get_file_md5(char *filepath, uint8_t *md5_result);

#endif
