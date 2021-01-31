#ifndef __QUERY_H
#define __QUERT_H

#include <stdint.h>

/* Obtain the first available component record for the given MD5 hash */
void get_component_record(uint8_t *md5, uint8_t *record);
void extract_csv(char *out, char *in, int n, long limit);

#endif
