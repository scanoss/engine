// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/mz.c
 *
 * MZ archive functions
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
  * @file mz.c
  * @date 7 Feb 2021 
  * @brief Contains the functions used for uncompress file contents using mz lib.
  
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/mz.c
  */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "ldb.h"
#include "decrypt.h"

/**
 * @brief uncompress the file contents of a given md5 key
 * @param key md5 key
 */
void mz_file_contents(char *key)
{

	/* Extract values from command */
	char dbtable[] = "oss/sources";

	/* Reserve memory for compressed and uncompressed data */
	char *src = calloc(MZ_MAX_FILE + 1, 1);
	uint8_t *zsrc = calloc((MZ_MAX_FILE + 1) * 2, 1);

	/* Define mz_job values */
	struct mz_job job;
	sprintf(job.path, "%s/%s", ldb_root, dbtable);
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

	cat_decrypted_mz(&job, key);

	free(src);
	free(zsrc);
}
