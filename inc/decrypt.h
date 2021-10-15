#ifndef __DECRYPT_H
    #define __DECRYPT_H

#include "scanoss.h"
void decrypt_data(uint8_t *data, uint32_t size, char *table, uint8_t *key, uint8_t *subkey);
void cat_decrypted_mz(struct mz_job *job, char *key);

#endif
