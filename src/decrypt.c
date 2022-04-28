#include <stdint.h>
#include "scanoss.h"
#include "debug.h"
#include "decrypt.h"
/**
  * @file decrypt.c
  * @date 27 Jun 2021 
  * @brief Contains the functions used for the LDB decryptation (if it is encrypted).
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/decrypt.c
  */

char * (*decrypt_data) (uint8_t *data, uint32_t size, char *table, uint8_t *key, uint8_t *subkey);
void  (*decrypt_mz) (uint8_t *data, uint32_t len);
/**
 * @brief Decrypt data function pointer. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param data //TODO  
 * @param size //TODO
 * @param table //TODO
 * @param key //TODO
 * @param subkey //TODO
 */
char * standalone_decrypt_data(uint8_t *data, uint32_t size, char *table, uint8_t *key, uint8_t *subkey)
{
	char * msg = NULL;
  
  if (!strcmp(table, "file"))
    msg = strndup((char*) data + 16, size - 16);
  else
    msg = strndup((char*) data, size);
  
  return msg;

}