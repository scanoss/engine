// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/quality.c
 *
 * "Quality" data aggregation functions
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
  * @file quality.c
  * @date 27 Nov 2020 
  * @brief Contains the functions used to print the quality section
  
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/quality.c
  */

#include <stdbool.h>
#include <stdint.h>

#include "quality.h"
#include "limits.h"
#include "debug.h"
#include "util.h"
#include "parse.h"
#include "decrypt.h"

/** @brief */
const char *quality_sources[] = {"best_practices"};

/**
 * @brief Print the quality item in STDOUT. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details. 
 * @param key //TODO
 * @param subkey //TODO
 * @param subkey_ln //TODO
 * @param data //TODO
 * @param datalen //TODO
 * @param iteration //TODO
 * @param ptr //TODO
 * @return //TODO
 */
bool print_quality_item(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	
	char ** out  = ptr;
	char *csv = (char*) data;
	char *source  = calloc(MAX_JSON_VALUE_LEN, 1);
	char *quality = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(source, csv, 1, MAX_JSON_VALUE_LEN);
	extract_csv(quality, csv, 2, MAX_JSON_VALUE_LEN);

	int src = atoi(source);

	scanlog("Fetched quality %s\n", quality);

	string_clean(quality);

	char result[MAX_FIELD_LN] = "\0";
	int len = 0;

	if (*quality && (src < (sizeof(quality_sources) / sizeof(quality_sources[0]))))
	{
		len += sprintf(result+len,"{");
		if (!src)
		{
			int q = atoi(quality);
			len += sprintf(result+len,"\"score\": \"%d/5\",", q);
		}
		else
			len += sprintf(result+len,"\"score\": \"%s\",", quality);
		len += sprintf(result+len,"\"source\": \"%s\"", quality_sources[atoi(source)]);
		len += sprintf(result+len,"}");
		*out = strdup(result);
	}


	free(source);
	free(quality);

	return true;
}

/**
 * @brief Query LDB for the quality item from a match
 * @param match input match
 */
void print_quality(match_data_t * match)
{
	if (!ldb_table_exists(oss_quality.db, oss_quality.table)) //skip purl if the table is not present
		return;
	
	char result[MAX_FIELD_LN] = "\0";
	char * aux = NULL;

	sprintf(result,"\"quality\": [");


	fetch_recordset(oss_quality, match->file_md5, print_quality_item, &aux);	
	
	free(match->quality_text);	
	asprintf(&match->quality_text, "%s%s]", result, aux ? aux : "");
	free(aux);

}

