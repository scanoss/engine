// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/cryptography.c
 *
 * Cryptography data aggregation functions
 *
 * Copyright (C) 2018-2021 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
  * @file cryptography.c
  * @date 28 Feb 2021 
  * @brief Contains the functions used for generate cryptography information for a match.
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/cryptography.c
  */

#include <stdbool.h>
#include <stdint.h>

#include "cryptography.h"
#include "limits.h"
#include "debug.h"
#include "util.h"
#include "parse.h"
#include "decrypt.h"

/**
 * @brief print crypto item LDB function pointer. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO  
 * @param subkey //TODO 
 * @param subkey_ln //TODO  
 * @param data //TODO 
 * @param datalen //TODO  
 * @param iteration //TODO 
 * @param ptr //TODO 
 * @return //TODO  
 */
bool print_crypto_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	match_data_t *match = ptr;

	if (!datalen) return false;
	char * CSV = decrypt_data(data, datalen, oss_cryptography, key, subkey);

	char *algorithm = calloc(MAX_JSON_VALUE_LEN, 1);
	char *strength = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(algorithm, CSV, 1, MAX_JSON_VALUE_LEN);
	extract_csv(strength, CSV, 2, MAX_JSON_VALUE_LEN);
	free(CSV);

	/* Calculate CRC to avoid duplicates */
	uint32_t CRC = string_crc32c(algorithm) + string_crc32c(strength);
	bool dup = add_CRC(match->crclist, CRC);

	scanlog("Fetched cryptography %s (%s)\n", algorithm, strength);
	
	/* Skip duplicated/empty records. Nothing must be appended in that case,
	   otherwise crytography_text becomes a non NULL empty string and the next
	   valid record would be prefixed with a stray comma: "cryptography": [,{...}] */
	if (dup || !*algorithm)
	{
		scanlog("Cryptography record ignored (%s), iteration %d\n", dup ? "duplicated" : "empty algorithm", iteration);
	}
	else
	{
		/* Big enough to hold the two extracted fields plus the json decoration */
		char result[2 * MAX_JSON_VALUE_LEN + MAX_FIELD_LN];
		/* A leading comma is only valid once an item has actually been emitted,
		   the iteration number is not a reliable indicator since records can be skipped */
		int len = snprintf(result, sizeof(result),
				"%s{\"algorithm\": \"%s\",\"strength\": \"%s\"}",
				(match->crytography_text && *match->crytography_text) ? "," : "",
				algorithm, strength);

		/* A truncated item would break the json, drop the record instead */
		if (len < 0 || len >= (int) sizeof(result))
			scanlog("Cryptography record ignored, json item too long (%d bytes)\n", len);
		else
			str_cat_realloc(&match->crytography_text, result);
	}

	free(algorithm);
	free(strength);

	return false;
}

/**
 * @brief print the cryptography section for a match
 * @param match to be processed
 */
void print_cryptography(match_data_t * match)
{
	if (!ldb_table_exists(oss_cryptography.db, oss_cryptography.table)) //skip crypto if the table is not present
		return;
	
	char result[MAX_FIELD_LN] = "\0";
	int len = 0;
	
	len += sprintf(result,"\"cryptography\": [");
	match->crytography_text = NULL;
	uint32_t crclist[CRC_LIST_LEN];
	memset(crclist, 0, sizeof(crclist));
	match->crclist = crclist;
	
	ldb_fetch_recordset(NULL, oss_cryptography, match->file_md5, false, print_crypto_item, match);
	
	char * aux = NULL;
	asprintf(&aux, "%s%s]", result, (match->crytography_text && *match->crytography_text) ? match->crytography_text : "" );
	free(match->crytography_text);	
	match->crytography_text = aux;
}

