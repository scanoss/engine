// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/copyright.c
 *
 * "Copyright" data aggregation functions
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

#include "copyright.h"
#include "limits.h"
#include "parse.h"
bool get_first_copyright(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	if ((datalen + 1) >= MAX_COPYRIGHT) datalen = MAX_COPYRIGHT;
	data[datalen] = 0;
	strcpy(ptr, skip_first_comma((char *) data));
	return true;
}

void clean_copyright(char *out, char *copyright)
{
	int i;
	char byte[2] = "\0\0";

	for (i = 0; i < (MAX_COPYRIGHT - 1); i++)
	{
		*byte = copyright[i];
		if (!*byte) break;
		else if (isalnum(*byte)) out[i] = *byte; 
		else if (strstr(" @#^()[]-_+;:.<>",byte)) out[i] = *byte;
		else out[i] = '*';
	}
	out[i] = 0;
}

bool print_copyrights_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *CSV = calloc(datalen + 1, 1);
	memcpy(CSV, (char *) data, datalen);

	char *source  = calloc(MAX_JSON_VALUE_LEN, 1);
	char *copyright = calloc(MAX_COPYRIGHT, 1);

	extract_csv(source, CSV, 1, MAX_JSON_VALUE_LEN);
	free(CSV);

	clean_copyright(copyright, skip_first_comma((char *) data));

	int src = atoi(source);

	if (*copyright) //&& (src <= (sizeof(copyright_sources) / sizeof(copyright_sources[0])))) MODIFICADO!!!
	{
		if (iteration) printf(",\n"); else printf("\n");
		printf("        {\n");
		printf("          \"name\": \"%s\",\n", copyright);
		printf("          \"source\": \"%s\"\n", copyright_sources[atoi(source)]);
		printf("        }");
	}

	free(source);
	free(copyright);

	return false;
}

void get_copyright(match_data match, char *copyright)
{
	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "copyright");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	if (ldb_table_exists("oss", "copyright"))
		ldb_fetch_recordset(NULL, table, match.file_md5, false, get_first_copyright, copyright);
}

void print_copyrights(match_data match)
{
	printf("[");

	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "copyright");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	uint32_t records = 0;

	if (ldb_table_exists("oss", "copyright"))
	{
		records = ldb_fetch_recordset(NULL, table, match.file_md5, false, print_copyrights_item, NULL);
		if (!records)
			records = ldb_fetch_recordset(NULL, table, match.component_md5, false, print_copyrights_item, NULL);
		if (!records)
			records = ldb_fetch_recordset(NULL, table, match.pair_md5, false, print_copyrights_item, NULL);
	}

	if (records) printf("\n      ");
	printf("],\n");
}

