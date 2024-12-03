// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/dependency.c
 *
 * "Dependency" data aggregation functions
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
  * @file dependency.c
  * @date 27 Nov 2020 
  * @brief Contains the functions used for dependency analizys.
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/dependency.c
  */

#include <stdint.h>
#include <stdbool.h>

#include "decrypt.h"
#include "scanoss.h"
#include "dependency.h"
#include "limits.h"
#include "parse.h"
#include "query.h"
#include "util.h"
#include "debug.h"

const char *dependency_sources[] = {"component_declared"};

/**
 * @brief print dependencies item data function pointer. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO
 * @param subkey //TODO
 * @param subkey_ln //TODO
 * @param data //TODO
 * @param datalen //TODO
 * @param iteration //TODO
 * @param ptr //TODO
 * @return //TODO
 */
bool print_dependencies_item(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *CSV = decrypt_data(data, datalen, *table, key, subkey);
	component_data_t * comp = (component_data_t *) ptr;
	char *source = calloc(MAX_JSON_VALUE_LEN, 1);
	char *vendor = calloc(MAX_JSON_VALUE_LEN, 1);
	char *component = calloc(MAX_JSON_VALUE_LEN, 1);
	char *version = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(source, CSV, 1, MAX_JSON_VALUE_LEN);
	extract_csv(vendor, CSV, 2, MAX_JSON_VALUE_LEN);
	extract_csv(component, CSV, 3, MAX_JSON_VALUE_LEN);
	extract_csv(version, CSV, 4, MAX_JSON_VALUE_LEN);

	free(CSV);

	int src = atoi(source);
	string_clean(vendor);
	string_clean(component);
	string_clean(version);

	char result[MAX_FIELD_LN] = "\0";
	int len = 0;
	if (*vendor && *component)
	{
		if (comp->dependency_text) len += sprintf(result+len,",");
		len += sprintf(result+len,"{");
		len += sprintf(result+len,"\"vendor\": \"%s\",", vendor);
		len += sprintf(result+len,"\"component\": \"%s\",", component);
		len += sprintf(result+len,"\"version\": \"%s\",", json_remove_invalid_char(version));
		len += sprintf(result+len,"\"source\": \"%s\"", dependency_sources[src]);
		len += sprintf(result+len,"}");
	}

	str_cat_realloc(&comp->dependency_text, result);
	free(source);
	free(vendor);
	free(component);
	free(version);
	return false;
}

/**
 * @brief Print dependencies in stdout of a given match
 * @param match input match
 */
int print_dependencies(component_data_t * comp)
{
	if (!ldb_table_exists(oss_dependency.db, oss_dependency.table)) //skip dependencies if the table is not present
		return 0;
	
	char result[MAX_FIELD_LN] = "\0";
	int len = 0;
	comp->dependency_text = NULL;
	len += sprintf(result+len,"\"dependencies\": [");	

	uint32_t records = 0;

	/* Pull URL dependencies */
	records = fetch_recordset( oss_dependency, comp->url_md5, print_dependencies_item, NULL);
	if (records)
		scanlog("Dependency matches (%d) reported for url_hash\n", records);
	else
		scanlog("No dependency matches reported for url_hash\n");

	/* Pull purl@version dependencies */
	if (!records)
		for (int i = 0; i < MAX_PURLS && comp->purls[i]; i++)
		{
			uint8_t hash[oss_purl.key_ln];
			purl_version_md5(hash, comp->purls[i], comp->version);

			records = fetch_recordset( oss_dependency, hash, print_dependencies_item, comp);
			if (records)
			{
				scanlog("Dependency matches (%d) reported for %s@%s\n", records, comp->purls[i],comp->version);
				break;
			}
			else scanlog("No dependency matches reported for %s@%s\n", comp->purls[i], comp->version);
		}

	/* Pull purl@last_version dependencies */
	if (!records)
		for (int i = 0; i < MAX_PURLS && comp->purls[i]; i++)
		{
			uint8_t hash[oss_purl.key_ln];
			purl_version_md5(hash, comp->purls[i], comp->latest_version);

			records = fetch_recordset( oss_dependency, hash, print_dependencies_item, comp);
			if (records)
			{
				scanlog("Dependency matches (%d) reported for %s@%s\n", records, comp->purls[i],comp->latest_version);
				break;
			}
			else scanlog("No dependency matches reported for %s@%s\n", comp->purls[i],comp->latest_version);
		}

	char * aux = NULL;
	if (comp->dependency_text && *comp->dependency_text)
		asprintf(&aux, "%s%s]", result, comp->dependency_text);
	else
		asprintf(&aux, "%s]", result);

	free(comp->dependency_text);	
	comp->dependency_text = aux;
	comp->dependencies = records;
	return records;
}

