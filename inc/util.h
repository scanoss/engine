#ifndef __UTIL_H
    #define __UTIL_H
    
#include <stdint.h>
#include <stdbool.h>

void hex_to_bin(char *hex, uint32_t len, uint8_t *out);
void file_md5(char *filepath, uint8_t *md5_result);
char *md5_hex(uint8_t *md5);
bool md5cmp(uint8_t *md51, uint8_t *md52);
void component_vendor_md5(char *component, char *vendor, uint8_t *out);
void uint32_reverse(uint8_t *data);
void trim(char *str);
char *datestamp(void);
void print_datestamp(void);
void printable_only(char *text);

#endif