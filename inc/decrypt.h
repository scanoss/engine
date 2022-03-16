#ifndef __DECRYPT_H
    #define __DECRYPT_H

#include "scanoss.h"
int (*decode) (int op, unsigned char *key, unsigned char *nonce,
		        const char *buffer_in, int buffer_in_len, unsigned char *buffer_out);
                
char * decrypt_data(uint8_t *data, uint32_t size, char *table, uint8_t *key, uint8_t *subkey);
void cat_decrypted_mz(struct mz_job *job, char *key);

#endif
