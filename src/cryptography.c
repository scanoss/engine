// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/cryptography.c
 *
 * Cryptography data aggregation functions
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

#include "cryptography.h"
#include "limits.h"
#include "debug.h"
#include "util.h"
#include "parse.h"
#include "decrypt.h"

bool print_crypto_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	match_data *match = ptr;

	if (!datalen) return false;
	decrypt_data(data, datalen, "cryptography", key, subkey);

	char *CSV  = calloc(datalen + 1, 1);
	memcpy(CSV, data, datalen);

	char *algorithm = calloc(MAX_JSON_VALUE_LEN, 1);
	char *strength = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(algorithm, CSV, 1, MAX_JSON_VALUE_LEN);
	extract_csv(strength, CSV, 2, MAX_JSON_VALUE_LEN);
	free(CSV);

	/* Calculate CRC to avoid duplicates */
	uint32_t CRC = string_crc32c(algorithm) + string_crc32c(strength);
	bool dup = add_CRC(match->crclist, CRC);

	scanlog("Fetched cryptography %s (%s)\n", algorithm, strength);

	if (!dup && *algorithm)
	{
		if (iteration) printf(",\n"); else printf("\n");
		printf("        {\n");
		printf("          \"algorithm\": \"%s\",\n", algorithm);
		printf("          \"strength\": \"%s\"\n", strength);
		printf("        }");
	}

	free(algorithm);
	free(strength);

	return false;
}

void print_cryptography(match_data match)
{
	if (!ldb_table_exists(oss_cryptography.db, oss_cryptography.table)) //skip crypto if the table is not present
		return;
	printf("      \"cryptography\": ");
	printf("[");

	/* Clean crc list (used to avoid duplicates) */
	for (int i = 0; i < CRC_LIST_LEN; i++) match.crclist[i] = 0;

	uint32_t records = 0;

	records = ldb_fetch_recordset(NULL, oss_cryptography, match.file_md5, false, print_crypto_item, &match);

	if (records) printf("\n      ");
	printf("],\n");
}

