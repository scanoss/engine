#include "hpsm.h"
#include <string.h>

bool hpsm_enabled;

/* HPSM - Normalized CRC8 for each line */
char *hpsm_crc_lines = NULL;

/* HPSM function pointers */
char* (*hpsm_hash_file_contents) (char * data);
struct ranges (*hpsm) (char* data, char* md5);
struct ranges (*hpsm_process)(unsigned char* data, int length, char* md5);