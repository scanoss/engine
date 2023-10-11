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


#ifndef MZ_DEFLATE
#include <zlib.h>
/* This code is here to provide backward compatibility, this is duplicated in the newers versions of ldb*/
#define CHUNK_SIZE 1024

int uncompress_by_chunks(uint8_t **data, uint8_t *zdata, size_t zdata_len) {
    int ret;
    z_stream strm;
    unsigned char out[CHUNK_SIZE];
    size_t data_size = 0;  // Current size of decompressed data

    // Initialize the z_stream structure
    memset(&strm, 0, sizeof(strm));
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        fprintf(stderr, "inflateInit failed with error %d\n", ret);
        exit(EXIT_FAILURE);
    }
	*data = malloc(CHUNK_SIZE);
    // Process the compressed data
    strm.avail_in = zdata_len;  // Size of the compressed data
    strm.next_in = zdata;

    do {
        strm.avail_out = CHUNK_SIZE;
        strm.next_out = out;

        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR) {
            fprintf(stderr, "inflate failed with error Z_STREAM_ERROR\n");
            inflateEnd(&strm);
			mz_corrupted();
        }

        unsigned have = CHUNK_SIZE - strm.avail_out;

        // Realloc to increase the size of data
        *data = realloc(*data, data_size + have);
        if (*data == NULL) 
		{
            fprintf(stderr, "Error reallocating memory to store decompressed data");
            inflateEnd(&strm);
            exit(EXIT_FAILURE);
        }

        // Copy the decompressed data to the end of data
        memcpy(*data + data_size, out, have);
        data_size += have;
    } while (ret != Z_STREAM_END);

    // Free resources
    inflateEnd(&strm);
	return data_size;
}

void mz_deflate2(struct mz_job *job)
{
	/* Decompress data */
	job->data_ln = uncompress_by_chunks((uint8_t **) &job->data, job->zdata, job->zdata_ln);
	job->data_ln--;
}
#define MZ_DEFLATE(job) mz_deflate2(job)
#endif

/**
 * @brief Find a key and print the result
 * 
 * @param job input mz job
 * @param key key to be found
 */
void mz_get_key(struct mz_job *job, char *key)
{
	/* Calculate mz file path */
	char mz_path[LDB_MAX_PATH + MD5_LEN] = "\0";
	char mz_file_id[5] = "\0\0\0\0\0";
	memcpy(mz_file_id, key, 4);

	sprintf(mz_path, "%s/%s.mz", job->path, mz_file_id);
	scanlog("MZ path: %s \n", mz_path);

	if (decrypt_mz && access(mz_path, F_OK) != 0)
		strcat(mz_path, ".enc");
	/* Save path and key on job */
	job->key = calloc(MD5_LEN, 1);
	ldb_hex_to_bin(key, MD5_LEN * 2, job->key);	

	/* Read source mz file into memory */
	job->mz = file_read(mz_path, &job->mz_ln);

	/* Search and display "key" file contents */
	/* Recurse mz contents */
	uint64_t ptr = 0;
	while (ptr < job->mz_ln)
	{
		/* Position pointers */
		job->id = job->mz + ptr;
		uint8_t *file_ln = job->id + MZ_MD5;
		job->zdata = file_ln + MZ_SIZE;

		/* Get compressed data size */
		uint32_t tmpln;
		memcpy((uint8_t*)&tmpln, file_ln, MZ_SIZE);
		job->zdata_ln = tmpln;

		/* Get total mz record length */
		job->ln = MZ_MD5 + MZ_SIZE + job->zdata_ln;

		/* Pass job to handler */
		if (!memcmp(job->id, job->key + 2, MZ_MD5))
		{
			if (decrypt_mz)
			{
				decrypt_mz(job->id, job->zdata_ln);
			}
			/* Decompress */
			MZ_DEFLATE(job);

			job->data[job->data_ln] = 0;
			printf("%s", job->data);
			return;
		}
		/* Increment pointer */
		ptr += job->ln;
		if (ptr > job->mz_ln)
		{
			printf("%s integrity failed\n", job->path);
			exit(EXIT_FAILURE);
		}
	}
	free(job->key);
	free(job->mz);
}


/**
 * @brief uncompress the file contents of a given md5 key
 * @param key md5 key
 */
void mz_file_contents(char *key, char * db)
{
	/* Extract values from command */
	char dbtable[64];
	sprintf(dbtable,"%s/sources",db);

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

	mz_get_key(&job, key);

	free(src);
	free(zsrc);
}
