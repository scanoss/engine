// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/license.c
 *
 * "License" data aggregation functions
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
#include <stdbool.h>
#include <stdint.h>

#include "limits.h"
#include "license.h"
#include "debug.h"
#include "util.h"
#include "parse.h"

const char *license_sources[] = {"component_declared", "file_spdx_tag", "file_header"};


bool get_first_license_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *CSV = calloc(datalen + 1, 1);
	memcpy(CSV, (char *) data, datalen);

	extract_csv(ptr, CSV, 2, MAX_JSON_VALUE_LEN);
	free(CSV);

	return true;
}

bool print_licenses_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *CSV  = calloc(datalen + 1, 1);
	memcpy(CSV, data, datalen);

	char *source  = calloc(MAX_JSON_VALUE_LEN, 1);
	char *license = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(source, CSV, 1, MAX_JSON_VALUE_LEN);
	extract_csv(license, CSV, 2, MAX_JSON_VALUE_LEN);
	free(CSV);

	int src = atoi(source);

	scanlog("Fetched license %s\n", license);
	printable_only(license);
	bool reported = false;

	if (*license && (src < (sizeof(license_sources) / sizeof(license_sources[0]))))
	{
		if (iteration) printf(",\n"); else printf("\n");
		printf("        {\n");
		printf("          \"name\": \"%s\",\n", license);
		printf("          \"source\": \"%s\"\n", license_sources[atoi(source)]);
		printf("        }");
		reported = true;
	}

	free(source);
	free(license);

	return reported;
}

void get_license(match_data match, char *license)
{
	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "license");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	uint32_t records = 0;

	if (ldb_table_exists("oss", "license"))
	{
		records = ldb_fetch_recordset(NULL, table, match.file_md5, false, get_first_license_item, license);
		if (!records)
			records = ldb_fetch_recordset(NULL, table, match.url_md5, false, get_first_license_item, license);
		if (!records)
			records = ldb_fetch_recordset(NULL, table, match.pair_md5, false, get_first_license_item, license);
	}
}

void print_licenses(match_data match)
{
	printf("[");

	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "license");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	uint32_t records = 0;

	/* Print URL license */
	if (*match.license)
	{
		printf("        {\n");
		printf("          \"name\": \"%s\",\n", match.license);
		printf("          \"source\": \"%s\"\n", license_sources[0]);
		printf("        }");
	}

	/* Look for component or file license */
	else if (ldb_table_exists("oss", "license"))
	{
		records = ldb_fetch_recordset(NULL, table, match.file_md5, false, print_licenses_item, NULL);
		if (records) scanlog("File license returns hits\n");
		if (!records)
		{
			records = ldb_fetch_recordset(NULL, table, match.url_md5, false, print_licenses_item, NULL);
			if (records) scanlog("Component license returns hits\n");
		}
		if (!records)
		{
			records = ldb_fetch_recordset(NULL, table, match.pair_md5, false, print_licenses_item, NULL);
			if (records) scanlog("Vendor/component license returns hits\n");
		}
	}

	if (records) printf("\n      ");
	printf("],\n");
}

