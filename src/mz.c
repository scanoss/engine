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
#include "decrypt.h"
#include <ldb.h>
#include "debug.h"
#include <unistd.h>

/**
 * @brief Find a key and print the result
 * 
 * @param job input mz job
 * @param key key to be found
 */
void mz_get_key(struct ldb_table kb, char *key)
{
	/* Calculate mz file path */
	char mz_path[LDB_MAX_PATH + kb.key_ln];
	char mz_file_id[5] = "\0\0\0\0\0";
	struct mz_job job;
	job.key_ln = kb.key_ln -2;
	memcpy(mz_file_id, key, 4);
	sprintf(mz_path, "%s/%s/%s/%s.mz", ldb_root, kb.db, kb.table,mz_file_id);

	if (kb.definitions & LDB_TABLE_DEFINITION_ENCRYPTED)
	{
		if (decrypt_mz)
			strcat(mz_path, ".enc");
		else
		{
			fprintf(stderr, "Encoder lib not available. Install libscanoss_encoder.so and try again\n");
			exit(EXIT_FAILURE);
		}	
	}
	scanlog("MZ path: %s \n", mz_path);

	/* Save path and key on job */
	job.key = calloc(kb.key_ln, 1);
	ldb_hex_to_bin(key, kb.key_ln * 2, job.key);	

	/* Read source mz file into memory */
	job.mz = file_read(mz_path, &job.mz_ln);

	/* Search and display "key" file contents */
	/* Recurse mz contents */
	uint64_t ptr = 0;
	while (ptr < job.mz_ln)
	{
		/* Position pointers */
		job.id = job.mz + ptr;
		uint8_t *file_ln = job.id + job.key_ln;
		job.zdata = file_ln + MZ_SIZE;

		/* Get compressed data size */
		uint32_t tmpln;
		memcpy((uint8_t*)&tmpln, file_ln, MZ_SIZE);
		job.zdata_ln = tmpln;

		/* Get total mz record length */
		job.ln = job.key_ln + MZ_SIZE + job.zdata_ln;

		/* Pass job to handler */
		if (!memcmp(job.id, job.key + 2, job.key_ln))
		{
			if (kb.definitions & LDB_TABLE_DEFINITION_ENCRYPTED)
			{
				decrypt_mz(kb.key_ln, job.id, job.zdata_ln);
			}
			/* Decompress */
			MZ_DEFLATE(&job);

			//job.data[job.data_ln] = 0;
			printf("%s", job.data);
			return;
		}
		/* Increment pointer */
		ptr += job.ln;
		if (ptr > job.mz_ln)
		{
			printf("%s integrity failed\n", job.path);
			exit(EXIT_FAILURE);
		}
	}
	free(job.key);
	free(job.mz);
}
