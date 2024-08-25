#ifndef __URL_H
    #define __URL_H

#include "scanoss.h"
#include "match_list.h"

bool handle_url_record(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr);

/* Calculates a main project URL from the PURL */
void fill_main_url(component_data_t *match);

/* Fetch related purls */
void fetch_related_purls(component_data_t *component);

/* Handler function for getting the oldest URL */
bool get_oldest_url(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr);

bool get_purl_first_release(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr);

void purl_release_date(char *purl, char *date);

bool purl_vendor_component_check(component_data_t * component);

int purl_source_check(component_data_t * component);


#endif
