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
#define DEPENDENCY_SOURCES_COUNT (sizeof(dependency_sources) / sizeof(dependency_sources[0]))

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
bool print_dependencies_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	component_data_t * comp = (component_data_t *) ptr;
	if (!comp)
	{
		scanlog("Dependency record ignored: no component context\n");
		return false;
	}

	char *CSV = decrypt_data(data, datalen, oss_dependency, key, subkey);
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
	/* Keep the source index inside the known sources, a corrupted record must not
	   be able to dereference outside of dependency_sources[] */
	if (src < 0 || src >= (int) DEPENDENCY_SOURCES_COUNT)
	{
		scanlog("Dependency record with unknown source id (%d), defaulting to %s\n", src, dependency_sources[0]);
		src = 0;
	}

	string_clean(vendor);
	string_clean(component);
	string_clean(version);

	/* Skip incomplete/corrupted records. Nothing must be appended in that case,
	   otherwise dependency_text becomes a non NULL empty string and the next
	   valid record would be prefixed with a stray comma: "dependencies": [,{...}] */
	if (!*vendor || !*component)
	{
		scanlog("Dependency record ignored (empty vendor or component), iteration %d\n", iteration);
	}
	else
	{
		/* Big enough to hold the three extracted fields plus the json decoration */
		char result[3 * MAX_JSON_VALUE_LEN + MAX_FIELD_LN];
		/* A leading comma is only valid once an item has actually been emitted */
		int len = snprintf(result, sizeof(result),
				"%s{\"vendor\": \"%s\",\"component\": \"%s\",\"version\": \"%s\",\"source\": \"%s\"}",
				(comp->dependency_text && *comp->dependency_text) ? "," : "",
				vendor, component, json_remove_invalid_char(version), dependency_sources[src]);

		/* A truncated item would break the json, drop the record instead */
		if (len < 0 || len >= (int) sizeof(result))
			scanlog("Dependency record ignored, json item too long (%d bytes)\n", len);
		else
			str_cat_realloc(&comp->dependency_text, result);
	}

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
	records = ldb_fetch_recordset(NULL, oss_dependency, comp->url_md5, false, print_dependencies_item, comp);
	if (records)
		scanlog("Dependency matches (%d) reported for url_hash\n", records);
	else
		scanlog("No dependency matches reported for url_hash\n");

	/* Pull purl@version dependencies */
	if (!records)
		for (int i = 0; i < MAX_PURLS && comp->purls[i]; i++)
		{
			uint8_t md5[MD5_LEN];
			purl_version_md5(md5, comp->purls[i], comp->version);

			records = ldb_fetch_recordset(NULL, oss_dependency, md5, false, print_dependencies_item, comp);
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
			uint8_t md5[MD5_LEN];
			purl_version_md5(md5, comp->purls[i], comp->latest_version);

			records = ldb_fetch_recordset(NULL, oss_dependency, md5, false, print_dependencies_item, comp);
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

