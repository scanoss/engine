// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/shainfo.c
 *
 * SHA1GIt data aggregation functions
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
  * @file shainfo.c
  * @date 28 Feb 2021 
  * @brief Contains the functions used for generate sha1git information for a match.
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/shainfo.c
  */

#include <stdbool.h>
#include <stdint.h>

#include "shainfo.h"
#include "limits.h"
#include "debug.h"
#include "util.h"
#include "parse.h"
#include "decrypt.h"

/**
 * @brief print SHA1_GIT hash item LDB function pointer. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO  
 * @param subkey //TODO 
 * @param subkey_ln //TODO  
 * @param data //TODO 
 * @param datalen //TODO  
 * @param iteration //TODO 
 * @param ptr //TODO 
 * @return //TODO  
 */
bool print_shagit_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	if (iteration>1) 
		return false;
	
	match_data_t *match = ptr;
	char result[MAX_FIELD_LN] = "\0";
	if (!datalen) return false;
	char *CSV  = calloc(datalen + 1, 1);
	memcpy(CSV, data, datalen);
	char *sha = calloc(MAX_JSON_VALUE_LEN, 1);
	extract_csv(sha, CSV, 1, MAX_JSON_VALUE_LEN);
	free(CSV);
	sprintf(result,"\"%s\"", sha);
	str_cat_realloc(&match->shagit_text, result);
	free(sha);
	return false;
}

/**
 * @brief print the SHA1_GIT section for a match
 * @param match to be processed
 */
void print_shagit_info(match_data_t * match)
{	
	if (!ldb_table_exists(oss_shagit.db, oss_shagit.table)) //skip crypto if the table is not present
		return;
	
	match->shagit_text = NULL;
	ldb_fetch_recordset(NULL, oss_shagit, match->file_md5, false, print_shagit_item, match);
	if (match->shagit_text==NULL)
	asprintf(&match->shagit_text, "\"N/A\"" );
}

