// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/attributions.c
 *
 * Attribution notices functions
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
#include "attributions.h"

bool notices_handler(uint8_t *key, uint8_t *subkey, int subkey_ln, \
uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	if (datalen != 2 * MD5_LEN) return false;
	char hexkey[MD5_LEN * 2 + 1];
	memcpy(hexkey, data, MD5_LEN * 2);
	hexkey[MD5_LEN * 2] = 0;

	/* Define mz_job values */
	char *src = calloc(MZ_MAX_FILE + 1, 1);
	uint8_t *zsrc = calloc((MZ_MAX_FILE + 1) * 2, 1);
	struct mz_job job;
	sprintf(job.path, "%s/oss/notices", ldb_root);
	memset(job.mz_id, 0, 2);
	job.mz = NULL;
	job.mz_ln = 0;
	job.id = NULL;
	job.ln = 0;
	job.data = src;        // Uncompressed data
	job.data_ln = 0;
	job.zdata = zsrc;      // Compressed data
	job.zdata_ln = 0;
	job.md5[MD5_LEN] = 0;
	job.key = NULL;

	/* Print attribution notice header */
	char *component = (char *) ptr;
	printf("[%s]\n", component);

	/* Print attribution notice */
	mz_cat(&job, hexkey);
	printf("\n");

	free(src);
	free(zsrc);

	return false;
}

bool attribution_handler(uint8_t *key, uint8_t *subkey, int subkey_ln, \
uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	bool *valid = (bool *) ptr;

	if (datalen != MD5_LEN) return false;

	/* Convert key */
	uint8_t attr_id[16];
	ldb_hex_to_bin((char *) data, MD5_LEN * 2, attr_id);

	/* Define mz_job values */
	struct mz_job job;
	sprintf(job.path, "%s/oss/notices", ldb_root);
	memset(job.mz_id, 0, 2);
	job.mz = NULL;
	job.mz_ln = 0;
	job.id = NULL;
	job.ln = 0;
	job.md5[MD5_LEN] = 0;
	job.key = NULL;

	/* If file does not exist, exit with valid = false */
	if (!mz_key_exists(&job, attr_id))
	{
		*valid = false;
		return true;
	}

	return false;
}

bool purl_notices_exist(struct ldb_table oss_attribution, uint8_t *key)
{
	bool validated = true;
	ldb_fetch_recordset(NULL, oss_attribution, key, false, attribution_handler, &validated);
	return validated;
}

bool print_notices(struct ldb_table oss_attribution, uint8_t *key, char *component)
{
	bool validated = true;
	ldb_fetch_recordset(NULL, oss_attribution, key, false, notices_handler, component);
	return validated;
}

bool check_purl_attributions(struct ldb_table oss_attributions, char *purls)
{
	bool valid = true;

  /* Read comma separated tokens from purl_list */
  char *purl = strtok(purls, ",");
  while (purl)
  {
		uint8_t md5[16];
    
		if (purl)
		{
			/* Get purl md5 */
			MD5((uint8_t *)purl, strlen(purl), md5);
			if (!ldb_key_exists(oss_attributions, md5))
			{
				printf("No attribution notices for %s\n", purl);
				valid = false;
			}
			else if (!purl_notices_exist(oss_attributions, md5))
			{
				printf("Missing notices for %s\n", purl);
				valid = false;
			}
		}
		purl = strtok(NULL, ",");
  }
	return valid;
}

void print_purl_attribution_notices(struct ldb_table oss_attributions, char *pairs)
{
  /* Read comma separated tokens from pair_list */
  char *pair = strtok(pairs, ",");
  while (pair)
  {
		uint8_t md5[16];
    
		if (pair)
		{
			/* Get vendor/component pair */
			MD5((uint8_t *)pair, strlen(pair), md5);
			print_notices(oss_attributions, md5, pair);
		}
		pair = strtok(NULL, ",");
  }
}

int attribution_notices(char *sbom)
{
	/* Validate SBOM */
	char *purl_list = parse_sbom(sbom, false, false, true);
	if (!check_purl_attributions(oss_attribution, purl_list)) exit(EXIT_FAILURE);

	/* Print attribution notices */
	print_purl_attribution_notices(oss_attribution, purl_list);
	free(purl_list);

	return EXIT_SUCCESS;
}
