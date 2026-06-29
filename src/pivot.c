// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/pivot.c
 *
 * Project structure reconstruction from the pivot table.
 *
 * Given a project's url hash, the pivot table yields the file keys belonging to
 * that project; for each file key the file table (and optionally the path table)
 * is queried to resolve the path(s), producing a "md5,path" listing.
 *
 * Copyright (C) 2018-2021 SCANOSS.COM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "scanoss.h"
#include <stdio.h>
#include "decrypt.h"
#include "debug.h"
#include "file.h"

struct get_path_s {
	char **paths;
	uint8_t * url_key;
	int paths_index;
};

/**
 * @brief ldb record handler for the file table. Collects every path associated
 * with a file key that belongs to the requested url_key.
 */
bool get_file_path_hash(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	if (datalen < table->key_ln)
		return false;
	struct get_path_s * get_path_url = ptr;
	/* If the url key does not match, this is not a useful record */
	if (memcmp(get_path_url->url_key, data, table->key_ln))
		return false;

	char * decrypted = NULL;

	if (path_table_present)
		decrypted = path_query(&data[table->key_ln]);
	else
		decrypted = decrypt_data(data, datalen, *table, key, subkey);

	get_path_url->paths = realloc(get_path_url->paths, (get_path_url->paths_index + 1) * sizeof(char*));
	get_path_url->paths[get_path_url->paths_index] = decrypted;
	get_path_url->paths_index++;
	return true;
}

/**
 * @brief ldb record handler for the pivot table. For each file key of the
 * project, resolves its path(s) and appends "<file_key_hex>,<path>" lines.
 */
bool get_project_hashes(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	uint8_t * file_key = data;
	struct get_path_s get_path = {.url_key = key, .paths = NULL, .paths_index = 0};
	char key_hex[oss_url.key_ln*2+1];
	ldb_bin_to_hex(file_key, table->key_ln, key_hex);

	ldb_fetch_recordset(NULL, oss_file, file_key, false, get_file_path_hash, (void *)&get_path);
	char * output = ptr;
	char * line = NULL;
	for (int i = 0; i < get_path.paths_index; i++)
	{
		if (!get_path.paths[i])
			continue;
		asprintf(&line, "%s,%s\n", key_hex, get_path.paths[i]);
		free(get_path.paths[i]);
		strcat(output, line);
		free(line);
	}

	free(get_path.paths);
	return false;
}

/**
 * @brief Reconstruct and print a project's file structure (md5,path per file)
 * given its url hash (MD5 or CRC64, sized by oss_url.key_ln).
 * @param url_key_hex project url hash in hex
 */
void get_project_files(char * url_key_hex)
{
	uint8_t url_key[oss_url.key_ln];
	scanlog("Reconstructing project structure for url %s\n", url_key_hex);
	if (!ldb_table_exists(oss_pivot.db, oss_pivot.table))
	{
		printf("the pivot table must be present to use this functionality\n");
		exit(EXIT_FAILURE);
	}
	ldb_hex_to_bin(url_key_hex, oss_url.key_ln*2, url_key);
	char * out = calloc(1, 1024*1024*500);
	ldb_fetch_recordset(NULL, oss_pivot, url_key, false, get_project_hashes, (void *)out);
	printf("%s", out);
	free(out);
}
