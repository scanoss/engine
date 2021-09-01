// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/copyright.c
 *
 * "Copyright" data aggregation functions
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

#include "copyright.h"
#include "limits.h"
#include "parse.h"
#include "util.h"
#include "decrypt.h"

const char *copyright_sources[] = {"component_declared", "file_header", "license_file", "scancode"};

static bool get_first_copyright(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	decrypt_data(data, datalen, "copyright", key, subkey);
	if ((datalen + 1) >= MAX_COPYRIGHT) datalen = MAX_COPYRIGHT;
	data[datalen] = 0;
	strcpy(ptr, skip_first_comma((char *) data));
	return true;
}

static void clean_copyright(char *out, char *copyright)
{
	int i;
	char byte[2] = "\0\0";

	for (i = 0; i < (MAX_COPYRIGHT - 1); i++)
	{
		*byte = copyright[i];
		if (!*byte) break;
		else if (isalnum(*byte)) out[i] = *byte; 
		else if (strstr(" @#^()[]-_+;:.<>",byte)) out[i] = *byte;
		else out[i] = ' ';
	}
	out[i] = 0;
}

static bool print_copyrights_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	match_data *match = ptr;

	decrypt_data(data, datalen, "copyright", key, subkey);

	char *CSV = calloc(datalen + 1, 1);
	memcpy(CSV, (char *) data, datalen);

	char *source  = calloc(MAX_JSON_VALUE_LEN + 1, 1);
	char *copyright = calloc(MAX_COPYRIGHT + 1, 1);

	extract_csv(source, CSV, 1, MAX_JSON_VALUE_LEN);

	clean_copyright(copyright, skip_first_comma((char *) CSV));
	free(CSV);

	/* Calculate CRC to avoid duplicates */
	uint32_t CRC = string_crc32c(source) + string_crc32c(copyright);
	bool dup = add_CRC(match->crclist, CRC);

	int src = atoi(source);

	if (!dup && (*copyright) && (src <= (sizeof(copyright_sources) / sizeof(copyright_sources[0]))))
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
	ldb_fetch_recordset(NULL, oss_copyright, match.file_md5, false, get_first_copyright, copyright);
}

void print_copyrights(match_data match)
{
	printf("[");

	/* Clean crc list (used to avoid duplicates) */
	for (int i = 0; i < CRC_LIST_LEN; i++) match.crclist[i] = 0;

	uint32_t records = 0;

	records = ldb_fetch_recordset(NULL, oss_copyright, match.file_md5, false, print_copyrights_item, &match);
	if (!records)
		records = ldb_fetch_recordset(NULL, oss_copyright, match.url_md5, false, print_copyrights_item, &match);
	if (!records)
		for (int i = 0; i < MAX_PURLS && *match.purl[i]; i++)
			records += ldb_fetch_recordset(NULL, oss_copyright, match.purl_md5[i], false, print_copyrights_item, &match);
	if (!records)
		records = ldb_fetch_recordset(NULL, oss_copyright, match.pair_md5, false, print_copyrights_item, &match);

	if (records) printf("\n      ");
	printf("],\n");
}
