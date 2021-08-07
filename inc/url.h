#ifndef __URL_H
    #define __URL_H

#include "scanoss.h"

bool handle_url_record(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr);

/* Calculates a main project URL from the PURL */
void fill_main_url(match_data *match);

/* Fetch related purls */
void fetch_related_purls(match_data *match);

#endif
