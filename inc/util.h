#ifndef __UTIL_H
    #define __UTIL_H

#include <stdint.h>
#include <stdbool.h>
#include <scanoss.h>
#include "component.h"

/* Reverse an uint32 number  */
void uint32_reverse(uint8_t *data);

/* Converts hex to binary */
void hex_to_bin(char *hex, uint32_t len, uint8_t *out);

/* Compares two MD5 checksums */
bool md5cmp(uint8_t *md51, uint8_t *md52);

/* Trim str */
void trim(char *str);

/* Returns the pair md5 of "component/vendor" */
void vendor_component_md5(char *component, char *vendor, uint8_t *out);

/* Returns the current date stamp */
char *datestamp(void);

/* Prints a "created" JSON element with the current datestamp */
void print_datestamp(void);


/* Returns a string with a hex representation of md5 */
char *md5_hex(uint8_t *md5);

/* Removes chr from str */
void remove_char(char *str, char chr);

/* Case insensitive string start comparison,
	returns true if a starts with b or viceversa */
bool stristart(char *a, char *b);

/* Cleans str from unprintable characters or quotes */
char * string_clean(char *str);

/* Calculates crc32c for a string */
uint32_t string_crc32c(char *str);

/* Searches crc in a crc list */
bool add_CRC(uint32_t *list, uint32_t crc);

/* Check if a string starts with the given start string */
bool starts_with(char *str, char *start);

/* Returns a pointer to field n in data */
char *field_n(int n, char *data);

/* Returns true if str is a valid MD5 hash */
bool valid_md5(char *str);

char * json_remove_invalid_char(char * input);
char * str_cat_realloc(char **a, char * b);

 void flip_slashes(char *data);

void free_and_null(void ** pr);

int path_is_third_party(component_data_t *comp);

/* Counts the number of '/' characters in a path string */
int path_depth(char* path);

/* Detects binary file type and validates if PURL matches file extension */
bool binary_file_to_purl(component_data_t *comp);

#endif
