#include <stdint.h>
#include "scanoss.h"

/**
  * @file decrypt.c
  * @date 27 Jun 2021 
  * @brief //TODO
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/decrypt.c
  */

/**
 * @brief Decrypt data
 * @param data //TODO  
 * @param size //TODO
 * @param table //TODO
 * @param key //TODO
 * @param subkey //TODO
 */
void decrypt_data(uint8_t *data, uint32_t size, char *table, uint8_t *key, uint8_t *subkey)
{
	/* Add here your decryption routines if needed */
}

/* Decrypt mz data */
void cat_decrypted_mz(struct mz_job *job, char *key)
{
	if (ldb_valid_table("oss/sources")) mz_cat(job, key);
}
