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
#include "debug.h"

static char * copyright_id_to_source_name(int id)
{
	switch (id)
	{
		case 1:
		case 5:
			return "file_header";
		case 0:
		case 2:
		case 6:
		case 8:
			return "license_file";
		case 3:
		case 4:
		case 7:
			return "scancode";
		default:
			return NULL;
	}
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
static bool print_copyrights_item(struct ldb_table *table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	component_data_t * comp = ptr;
	char * CSV = decrypt_data(data, datalen, *table, key, subkey);

	char *source  = calloc(MAX_JSON_VALUE_LEN + 1, 1);
	char *copyright = calloc(MAX_COPYRIGHT + 1, 1);

	extract_csv(source, CSV, 1, MAX_JSON_VALUE_LEN);

	clean_copyright(copyright, skip_first_comma((char *) CSV));
	free(CSV);
	/* Calculate CRC to avoid duplicates */
	uint32_t CRC = string_crc32c(source) + string_crc32c(copyright);
	bool dup = add_CRC(comp->crclist, CRC);

	int src = atoi(source);

	char result[MAX_FIELD_LN] = "\0";
	int len = 0;
	char * source_id = copyright_id_to_source_name(src);
	if (!dup && (*copyright) && source_id)
	{
		if (comp->copyright_text) 
			len += sprintf(result+len,",");
		len += sprintf(result+len,"{\"name\": \"%s\",", copyright);
		len += sprintf(result+len,"\"source\": \"%s\"}", source_id);
	}
	if (*result)
		str_cat_realloc(&comp->copyright_text, result);

	free(source);
	free(copyright);

	return false;
}


/**
 * @brief Print the copyrights items for a match throught stdout
 * @param match //TODO
 */
void print_copyrights(component_data_t * comp)
{
	if (!ldb_table_exists(oss_copyright.db, oss_copyright.table)) //skip purl if the table is not present
		return;
	scanlog("Process copyrights\n");
	char result[MAX_FIELD_LN] = "\0";
	int len = 0;

	comp->copyright_text = NULL;
	
	len += sprintf(result+len,"\"copyrights\": [");

	uint32_t crclist[CRC_LIST_LEN];
	memset(crclist, 0, sizeof(crclist));
	comp->crclist = crclist;
	
	uint32_t records = 0;

	records = ldb_fetch_recordset(NULL, oss_copyright, comp->file_md5_ref, false, print_copyrights_item, comp);
	scanlog("File md5 copyright records %d\n", records);
	if (!records)
	{
		records = ldb_fetch_recordset(NULL, oss_copyright, comp->url_md5, false, print_copyrights_item, comp);
		scanlog("URL md5 copyright records %d\n", records);

	}
	if (!records)
		for (int i = 0; i < MAX_PURLS && comp->purls[i]; i++)
			if (ldb_fetch_recordset(NULL, oss_copyright, comp->purls_md5[i], false, print_copyrights_item, comp)) break;

	char * aux = NULL;
	if (comp->copyright_text && *comp->copyright_text)
		asprintf(&aux, "%s%s]", result, comp->copyright_text);
	else
		asprintf(&aux, "%s]", result);

	free(comp->copyright_text);	
	comp->copyright_text = aux;
}
