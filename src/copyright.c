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

/**
  * @file copyright.c
  * @date 27 Nov 2020 
  * @brief Contains the code and functionalities related witht the copyright processing 
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/copyright.c
  */

#include "copyright.h"
#include "limits.h"
#include "parse.h"
#include "util.h"
#include "decrypt.h"

const char *copyright_sources[] = {"component_declared", "file_header", "license_file", "scancode"};

/**
 * @brief get fisrt copyright LDB function pointer. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO
 * @param subkey //TODO
 * @param subkey_ln //TODO
 * @param[out] data //TODO
 * @param datalen //TODO
 * @param iteration //TODO
 * @param ptr output pointer, returns the fisrt copyright obtained from the database
 * @return //TODO
 */
static bool get_first_copyright(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char * result = decrypt_data(data, datalen, "copyright", key, subkey);
	if (result)
		strncpy(ptr, skip_first_comma((char *) result), MAX_COPYRIGHT);
	
	free(result);
	return true;
}

/**
 * @brief //Remove undesired characteres from a copyright
 * @param[out] out ouput buffer pointer
 * @param copyright input buffer pointer
 */
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

/**
 * @brief Print a copyright item throught stdout.
 * @param key //TODO
 * @param subkey //TODO
 * @return //TODO
 */
static bool print_copyrights_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	match_data *match = ptr;

	char * CSV = decrypt_data(data, datalen, "copyright", key, subkey);

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
		if (iteration) printf(",");
		printf("{");
		printf("\"name\": \"%s\",", copyright);
		printf("\"source\": \"%s\"", copyright_sources[atoi(source)]);
		printf("}");
	}

	free(source);
	free(copyright);

	return false;
}

/**
 * @brief Query the copyright of a match to oss_copyright table using LDB.
 * @param match input match.
 * @param copyright output char buffer.
 */
void get_copyright(match_data match, char *copyright)
{
	if (!ldb_table_exists(oss_copyright.db, oss_copyright.table)) //skip purl if the table is not present
		return;

	ldb_fetch_recordset(NULL, oss_copyright, match.file_md5, false, get_first_copyright, copyright);
}

/**
 * @brief Print the copyrights items for a match throught stdout
 * @param match //TODO
 */
void print_copyrights(match_data match)
{
	if (!ldb_table_exists(oss_copyright.db, oss_copyright.table)) //skip purl if the table is not present
		return;
	printf(",\"copyrights\": ");
	printf("[");

	/* Clean crc list (used to avoid duplicates) */
	for (int i = 0; i < CRC_LIST_LEN; i++) match.crclist[i] = 0;

	uint32_t records = 0;

	records = ldb_fetch_recordset(NULL, oss_copyright, match.file_md5, false, print_copyrights_item, &match);
	if (!records)
		records = ldb_fetch_recordset(NULL, oss_copyright, match.url_md5, false, print_copyrights_item, &match);
	if (!records)
		for (int i = 0; i < MAX_PURLS && *match.purl[i]; i++)
			if (ldb_fetch_recordset(NULL, oss_copyright, match.purl_md5[i], false, print_copyrights_item, &match)) break;

	printf("]");
}
