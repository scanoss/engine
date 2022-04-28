#ifndef __DECRYPT_H
    #define __DECRYPT_H

#include "scanoss.h"

extern char * (*decrypt_data) (uint8_t *data, uint32_t size, char *table, uint8_t *key, uint8_t *subkey);
extern void  (*decrypt_mz) (uint8_t *data, uint32_t len);

char * standalone_decrypt_data(uint8_t *data, uint32_t size, char *table, uint8_t *key, uint8_t *subkey);

#endif
