// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/dependency.c
 *
 * "Dependency" data aggregation functions
 *
 * Copyright (C) 2018-2020 SCANOSS.COM
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
#include <stdint.h>
#include <stdbool.h>

#include "dependency.h"
#include "limits.h"
#include "parse.h"
#include "util.h"

const char *dependency_sources[] = {"component_declared"};

bool print_dependencies_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *CSV = calloc(datalen + 1, 1);
	memcpy(CSV, (char *) data, datalen);

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
	printable_only(vendor);
	printable_only(component);

	if (*vendor && *component)
	{
		if (iteration) printf(",\n"); else printf("\n");
		printf("        {\n");
		printf("          \"vendor\": \"%s\",\n", vendor);
		printf("          \"component\": \"%s\",\n", component);
		printf("          \"version\": \"%s\",\n", version);
		printf("          \"source\": \"%s\"\n", dependency_sources[src]);
		printf("        }");
	}

	free(source);
	free(vendor);
	free(component);
	free(version);
	return false;
}

void print_dependencies(match_data match)
{
	printf("[");

	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "dependency");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	uint32_t records = 0;

	if (ldb_table_exists("oss", "dependency"))
	{
		records = ldb_fetch_recordset(NULL, table, match.component_md5, false, print_dependencies_item, NULL);
		if (!records) 
			records = ldb_fetch_recordset(NULL, table, match.pair_md5, false, print_dependencies_item, NULL);
	}

	if (records) printf("\n      ");
	printf("],\n");
}

