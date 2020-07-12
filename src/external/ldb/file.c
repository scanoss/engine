// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/file.c
 *
 * File handling functions
 *
 * Copyright (C) 2018-2020 SCANOSS LTD
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

void ldb_prepare_dir(char *path)
{
	if (ldb_dir_exists (path)) return;
	if (mkdir (path, 0755)) 
		ldb_error ("E050 Cannot create root LDB directory");
}

bool ldb_file_exists(char *path)
{
	struct stat pstat;
	if (!stat(path, &pstat))
		if (S_ISREG(pstat.st_mode))
			return true;
	return false;
}

bool ldb_dir_exists(char *path)
{
	struct stat pstat;
	if (!stat(path, &pstat))
		if (S_ISDIR(pstat.st_mode))
			return true;
	return false;
}

/* Return the file size for path */
uint64_t ldb_file_size(char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp) return 0;

	fseeko64(fp, 0, SEEK_END);
	uint64_t size = ftello64(fp);
	fclose(fp);

	return size;
}

bool ldb_check_root()
{
	if (!ldb_dir_exists(ldb_root))
	{
		printf("E059 LDB root directory %s is not accessible\n", ldb_root);
		return false;
	}
	return true;
}

/* Checks if a db/table already exists */
bool ldb_table_exists(char *db, char*table)
{
	char *path = malloc(ldb_max_path);
	sprintf(path, "%s/%s/%s", ldb_root, db, table);
	bool out = ldb_dir_exists(path);
	free(path);
	return out;
}

/* Checks if a db already exists */

bool ldb_database_exists(char *db)
{
	char *path = malloc(ldb_max_path);
	sprintf(path, "%s/%s", ldb_root, db);
	bool out = ldb_dir_exists(path);
	free(path);
	return out;
}
