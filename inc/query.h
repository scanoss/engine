#ifndef __QUERY_H
#define __QUERT_H

#include <stdint.h>

/* Obtain the first available url record for the given MD5 hash */
void get_url_record(uint8_t *md5, uint8_t *record);
void purl_version_md5(uint8_t *out, char *purl, char *version);
int get_component_age(uint8_t *md5);

#endif
