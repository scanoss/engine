#include <stdint.h>
#include "scanoss.h"
#include "debug.h"

/**
  * @file decrypt.c
  * @date 27 Jun 2021 
  * @brief Contains the functions used for the LDB decryptation (if it is encrypted).
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/decrypt.c
  */

/**
 * @brief Decrypt data function pointer. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
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

/**
 * @brief Decrypt mz data
 * @param mz_job Job to decompress
 * @param key Decryption key
*/  
void cat_decrypted_mz(struct mz_job *job, char *key)
{
  scanlog("Decompres and cat");
  if (ldb_valid_table("oss/sources")) mz_cat(job, key);
  else
    scanlog("cannot open table sources");
}
