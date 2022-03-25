#include <stdint.h>
#include "scanoss.h"
#include "debug.h"
//#include <scanoss_encoder.h>
#include "decrypt.h"
/**
  * @file decrypt.c
  * @date 27 Jun 2021 
  * @brief Contains the functions used for the LDB decryptation (if it is encrypted).
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/decrypt.c
  */

unsigned char global_key[] = {0x6b,0x47,0xc0,0xa1,0x3f,0xab,0x5f,0x9b,0x94,0xa3,0x34,0x85,0xbe,0x5f,0x1c,0xf6,0x4c,0x07,0xa1,0x2f,0xfc,0x8c,0x3f,0x8c,0x35,0xc2,0x4d,0xd3,0xd7,0x5f,0x20,0x41};
#define DECOMPRESS 4
#define DECRYPT 2
/**
 * @brief Decrypt data function pointer. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param data //TODO  
 * @param size //TODO
 * @param table //TODO
 * @param key //TODO
 * @param subkey //TODO
 */
char * decrypt_data(uint8_t *data, uint32_t size, char *table, uint8_t *key, uint8_t *subkey)
{
	char * msg = NULL;
  /* Add here your decryption routines if needed */
  if (!strcmp(table, "file"))
	{
    if (decode)
    {
      msg = calloc(MAX_FILE_PATH * 2, 1);
      int msize = decode(4, NULL, NULL, (char *) data + MD5_LEN, size - MD5_LEN, (unsigned char *) msg);
      msg[msize] = 0;
    }
	  else
    {
      msg = strndup((char*) data + 16, size - 16);
    }
    return msg;
	}
  else if (!strcmp(table, "url"))
  {
    if (decode)
    {
      msg = calloc(LDB_MAX_REC_LN, 1);
      int msize = decode(DECRYPT, global_key, key, (char *) data, size, (unsigned char *) msg);
      msg[msize] = 0;
    }
	  else
    {
      msg = strndup((char*) data, size);
    }
    return msg;
  }
  else
    msg = strndup((char*) data, size);

  msg[size] = 0;

  return msg;

}

/**
 * @brief Decrypt mz data
 * @param mz_job Job to decompress
 * @param key Decryption key
*/  
void cat_decrypted_mz(struct mz_job *job, char *key)
{
  scanlog("Decompress and cat");
  if (ldb_valid_table("oss/sources")) mz_cat(job, key);
  else
    scanlog("cannot open table sources");
}