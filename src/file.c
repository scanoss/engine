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

/**
  * @file file.c
  * @date 12 Jul 2020 
  * @brief Contains the functions used for processing the file table from the KB.
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/file.c
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
#include "decrypt.h"
#include "ignorelist.h"
#include "parse.h"

/**
 * @brief Check is a given path is a file or not.
 * @param path string path
 * @return true is it is a file, false otherwise.
 */
bool is_file(char *path)
{
	struct stat pstat;
	if (!stat(path, &pstat))
		if (S_ISREG(pstat.st_mode))
			return true;
	return false;
}

/**
 * @brief Check f a given path is a dir or not
 * @param path string path
 * @return true is it is a dir, false otherwise.
 */
bool is_dir(char *path)
{
	struct stat pstat;
	if (!stat(path, &pstat))
		if (S_ISDIR(pstat.st_mode))
			return true;
	return false;
}

/**
 * @brief get size of a given file
 * @param path string path
 * @return file size
 */
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

/**
 * @brief read a file and put it into a buffer.
 * @param[out] out output buffer.
 * @param path file path.
 * @param maxlen max length to read.
 */
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

/**
 * @brief Calculate the MD5 for filepath contents.
 * @param filepath file path.
 * @param md5_result calculated md5.
 */
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

/**
 * @brief Return the number of directories in path
 * @return //TODO
 */
int dir_count(char *path)
{
	int count = 1;
	char *p = path;
	while (*p) if (*(p++) == '/') count++;
	return count;
}

/**
 * @brief Collect all files function pointer. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO
 * @param subkey //TODO
 * @param subkey_ln //TODO
 * @param raw_data //TODO
 * @param datalen //TODO
 * @param iteration //TODO
 * @param ptr //TODO
 * @return //TODO
 */
bool collect_all_files(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
{

	/* Leave if FETCH_MAX_FILES is reached */
	if (iteration >= FETCH_MAX_FILES) return true;

	/* Ignore path lengths over the limit */
	if (!datalen || datalen >= (MD5_LEN + MAX_FILE_PATH)) return false;

	/* Decrypt data */
	decrypt_data(raw_data, datalen, "file", key, subkey);

	/* Copy data to memory */
	file_recordset *files = ptr;
	int path_ln = datalen - MD5_LEN;
	memcpy(files[iteration].url_id, raw_data, MD5_LEN);
	memcpy(files[iteration].path, raw_data + MD5_LEN, path_ln);
	files[iteration].path[path_ln] = 0;
	files[iteration].path_ln = dir_count(files[iteration].path);

	scanlog("#%d File %s\n", iteration, files[iteration].path);
	return false;
}

/* Returns a pointer to the file extension of "path" */
char *file_extension(char *path)
{
	char *dot   = strrchr(path, '.');
	char *slash = strrchr(path, '/');
	if (!slash) slash = path;

	if (!dot) return NULL;
	if (dot > slash) return dot + 1;
	return NULL;
}


/**
 * @brief get first file function pointer. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO
 * @param subkey //TODO
 * @param subkey_ln //TODO
 * @param raw_data //TODO
 * @param datalen //TODO
 * @param iteration //TODO
 * @param ptr //TODO
 * @return //TODO
 */
/* Get the first file record and copy extension to ptr */
bool get_first_file(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	if (!datalen) return false;
        uint8_t file_data[MAX_PATH + 1] = "\0";

	decrypt_data(data, datalen, "file", key, subkey);
	memcpy(file_data, data, datalen);
	file_data[datalen] = 0;

	if (!*file_data) return false;

	*(char *)ptr = 0;
	char *ext = file_extension((char *)file_data + MD5_LEN);
	if (!ext) return true;

	strcpy((char *) ptr, ext);
	return true;
}
/**
 * @brief Get the extension of a given file into a ldb table.
 * @param md5 input mdz
 * @return string with the extension
 */
char *get_file_extension(uint8_t *md5)
{
	char *out = malloc(MAX_ARGLN + 1);
	*out = 0;

	ldb_fetch_recordset(NULL, oss_file, md5, false, get_first_file, out);
	return out;
}
