// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/health.c
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
  * @file health.c
  * @date 25 Oct 2022 
  * @brief Contains the functions to retrieve repository health information for a match.
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/health.c
  */

#include <stdbool.h>
#include <stdint.h>

#include "health.h"
#include "limits.h"
#include "debug.h"
#include "util.h"
#include "parse.h"
#include "decrypt.h"

/**
 * @brief Prints information about statistics of a component comming from GitHub or gitee
 * 
 */
bool print_health_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	component_data_t *match = ptr;

	char * decrypted = decrypt_data(data, datalen, oss_purl, key, subkey);

	/* Expect at least a date or a pkg:*/
	if (strlen(decrypted) < 9) 
	{	
		free(decrypted);
		return false;
	}

	/* Ignore purl relation records */
	if (!memcmp(decrypted, "pkg:", 4)) 
	{
		free(decrypted);
		return false;
	}

	/** Pick gitlab and gitee information*/
	char creation_date[MAX_FIELD_LN] = "\0";
    char last_update[MAX_FIELD_LN] = "\0";
    char last_push[MAX_FIELD_LN] = "\0";
    char watchers_count[MAX_FIELD_LN] = "\0";
    char issues_count[MAX_FIELD_LN] = "\0";
    char forks_count[MAX_FIELD_LN] = "\0";
	char provenance[MAX_FIELD_LN] = "\0";
       
	extract_csv(creation_date, decrypted, 1, MAX_FIELD_LN);
    extract_csv(last_update, decrypted, 2, MAX_FIELD_LN);
    extract_csv(last_push, decrypted, 3, MAX_FIELD_LN);
    extract_csv(watchers_count, decrypted, 4, MAX_FIELD_LN);
    extract_csv(issues_count, decrypted, 5, MAX_FIELD_LN);
    extract_csv(forks_count, decrypted, 6, MAX_FIELD_LN);
	extract_csv(provenance, decrypted, 7, MAX_FIELD_LN);

   	char result[MAX_FIELD_LN * 7] = "\0";
	
	int len = 0;

	len += sprintf(&result[len]," \"health\":{\"creation_date\":\"%s\", ", creation_date);
	len += sprintf(&result[len],"\"last_update\":\"%s\", ", last_update);
	len += sprintf(&result[len],"\"last_push\":\"%s\", ", last_push);
	len += sprintf(&result[len],"\"watchers\":%s, ", *watchers_count ? watchers_count : "null");
	len += sprintf(&result[len],"\"issues\":%s} ", *issues_count ? issues_count : "null");
	len += sprintf(&result[len],",\"provenance\":\"%s\"",provenance);

	match->health_text = strdup(result);

    free(decrypted);

	return false;
}

/**
 * @brief print the Health section for a match
 * @param component to be processed
 */
void print_health(component_data_t *component)
{
	if (!ldb_table_exists(oss_purl.db, oss_purl.table)) //skip crypto if the table is not present
		return;
	ldb_fetch_recordset(NULL, oss_purl, component->purls_md5[0], false, print_health_item, component);
}

