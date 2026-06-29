#ifndef __FILE_H
    #define __FILE_H

#include <stdint.h>
#include <stdbool.h>

struct ldb_table;

uint64_t get_file_size(char *path);
int read_file(char *out, char *path, uint64_t maxlen);
bool is_file(char *path);
bool is_dir(char *path);

void get_file_md5(char *filepath, uint8_t *md5_result);
bool collect_all_files(struct ldb_table *table, uint8_t *key, uint8_t *subkey, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr);
bool count_all_files(struct ldb_table *table, uint8_t *key, uint8_t *subkey, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr);
char *get_file_extension(uint8_t *md5);
char * path_query(uint8_t * file_id);

#endif
