// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/file.c
 *
 * File handling functions
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


#include <sys/stat.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "file.h"
#include "scanoss.h"
#include "limits.h"
#include "debug.h"

bool is_file(char *path)
{
	struct stat pstat;
	if (!stat(path, &pstat))
		if (S_ISREG(pstat.st_mode))
			return true;
	return false;
}

bool is_dir(char *path)
{
	struct stat pstat;
	if (!stat(path, &pstat))
		if (S_ISDIR(pstat.st_mode))
			return true;
	return false;
}

uint64_t get_file_size(char *path)
{
	uint64_t length = 0;
	FILE *file = fopen(path, "rb");
	if (file)
	{
		fseek(file, 0, SEEK_END);
		length = ftell(file);
		fclose(file);
	}
	return length;
}

void read_file(char *out, char *path, uint64_t maxlen)
{

	char *src;
	uint64_t length = 0;
	out[0] = 0;

	if (!is_file(path))
	{
		return;
	}

	FILE *file = fopen(path, "rb");
	if (file)
	{
		fseek(file, 0, SEEK_END);
		length = ftell(file);
		fseek(file, 0, SEEK_SET);
		src = calloc(length, 1);
		if (src)
		{
			fread(src, 1, length, file);
		}
		fclose(file);
		if (maxlen > 0)
			if (length > maxlen)
				length = maxlen;
		memcpy(out, src, length);
		free(src);
	}
}

/* Calculate the MD5 for filepath contents */
void get_file_md5(char *filepath, uint8_t *md5_result)
{

	/* Read file contents into buffer */
	FILE *in = fopen(filepath, "rb");
	fseek(in, 0L, SEEK_END);
	long filesize = ftell(in);

	if (!filesize)
	{
		MD5(NULL, 0, md5_result);
	}

	else
	{
		/* Read file contents */
		fseek(in, 0L, SEEK_SET);
		uint8_t *buffer = malloc(filesize);
		if (!fread(buffer, filesize, 1, in)) fprintf(stderr, "Warning: cannot open file %s\n", filepath);

		/* Calculate MD5sum */
		MD5(buffer, filesize, md5_result);
		free (buffer);
	}

	fclose(in);
}

bool collect_all_files(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
{

	/* Leave if FETCH_MAX_FILES is reached */
	if (iteration >= FETCH_MAX_FILES) return true;

	/* Ignore path lengths over the limit */
	if (!datalen || datalen >= (MD5_LEN + MAX_FILE_PATH)) return false;

	/* Copy data to memory */
	file_recordset *files = ptr;
	int path_ln = datalen - MD5_LEN;
	files[iteration].path_ln = path_ln;
	memcpy(files[iteration].url_id, raw_data, MD5_LEN);
	memcpy(files[iteration].path, raw_data + MD5_LEN, path_ln);
	files[iteration].path[path_ln] = 0;

	scanlog("#%d File %s\n", iteration, files[iteration].path);
	return false;
}



