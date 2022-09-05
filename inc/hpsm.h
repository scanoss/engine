#ifndef __HPSM_H
#define __HPSM_H

#include <stdbool.h>
#include <stdint.h>

struct ranges
{
	char *local;
	char *remote;
	char *matched;
};

extern bool hpsm_enabled;
extern bool hpsm_lib_present;
extern char *hpsm_crc_lines;

/****** HPSM public functions *******/
extern struct ranges (*hpsm) (char* data, char* md5);
extern char* (*hpsm_hash_file_contents) (char * data);
extern struct ranges (*hpsm_process)(unsigned char* data, int length, char* md5);
/******************************/

bool hpsm_lib_load(void);
void hpsm_lib_close(void);
struct ranges hpsm_calc(uint8_t * file_md5);

#endif
