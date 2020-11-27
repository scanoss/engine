// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/quality.c
 *
 * "Quality" data aggregation functions
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

bool print_quality_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *CSV  = calloc(datalen + 1, 1);
	memcpy(CSV, data, datalen);

	char *source  = calloc(MAX_JSON_VALUE_LEN, 1);
	char *quality = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(source, CSV, 1, MAX_JSON_VALUE_LEN);
	extract_csv(quality, CSV, 2, MAX_JSON_VALUE_LEN);
	free(CSV);

	int src = atoi(source);

	scanlog("Fetched quality %s\n", quality);

	printable_only(quality);

	bool reported = false;

	if (*quality && (src < (sizeof(quality_sources) / sizeof(quality_sources[0]))))
	{
		if (iteration) printf(",\n"); else printf("\n");
		printf("        {\n");
		if (!src) 
			printf("          \"score\": \"%s/5\",\n", quality);
		else
			printf("          \"score\": \"%s\",\n", quality);
		printf("          \"source\": \"%s\"\n", quality_sources[atoi(source)]);
		printf("        }");
		reported = true;
	}

	free(source);
	free(quality);

	return reported;
}

void print_quality(match_data match)
{
	printf("[");

	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "quality");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	uint32_t records = 0;

	if (ldb_table_exists("oss", "quality"))
	{
		records = ldb_fetch_recordset(NULL, table, match.file_md5, false, print_quality_item, NULL);
	}

	if (records) printf("\n      ");
	printf("],\n");
}

