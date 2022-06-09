#ifndef __HPSM_H
#define __HPSM_H

#include <stdbool.h>

struct ranges
{
	char *local;
	char *remote;
	char *matched;
};

extern bool hpsm_enabled;
extern char *hpsm_crc_lines;

extern char* (*hpsm_hash_file_contents) (char * data);
extern struct ranges (*hpsm) (char* data, char* md5);
extern struct ranges (*hpsm_process)(unsigned char* data, int length, char* md5);

#endif
