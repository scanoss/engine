// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/sector.c
 *
 * LDB sector handling routines
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

/* Opens an LDB sector and returns the file descriptor. If read mode, returns NULL
   in case it does not exist. Otherwise an empty sector file is created in case it
   does not exist */
FILE *ldb_open (struct ldb_table table, uint8_t *key, char *mode) {

	/* Create block (file) if it doesn't already exist */
	char *sector_path = ldb_sector_path(table, key, mode, table.tmp);
	if (!sector_path) return NULL;

	/* Open data block */
	FILE *out = fopen(sector_path, mode);
	free(sector_path);
	return out;
}

bool ldb_create_table(char *db, char *table, int keylen, int reclen)
{
	bool out = false;

	char *dbpath = malloc(ldb_max_path);
	sprintf(dbpath, "%s/%s", ldb_root, db);

	char *tablepath = malloc(ldb_max_path);
	sprintf(tablepath, "%s/%s/%s", ldb_root, db, table);

	if (!ldb_valid_name(db) || !ldb_valid_name(table))
	{
		printf("E064 Invalid characters or name is too long\n");
	}
	else if (!ldb_dir_exists(dbpath))
	{
		printf("E062 Database does not exist\n");
	}
	else if (ldb_dir_exists(tablepath))
	{
		printf("E069 Table already exists\n");
	}
	else {
		mkdir(tablepath, 0755);
		if (ldb_dir_exists(tablepath))
		{
			ldb_write_cfg(db, table, keylen, reclen);
			out = true;
		}
		else printf("E065 Cannot create %s\n", tablepath);
	}

	free(dbpath);
	free(tablepath);
	return out;
}

bool ldb_create_database(char *database)
{
	bool out = false;

	char *path = malloc(ldb_max_path);
	sprintf(path, "%s/%s", ldb_root, database);
	if (ldb_dir_exists(path))
	{
		printf("E068 Database already exists\n");
	}
	else {
		mkdir(path, 0755);
		if (ldb_dir_exists(path))
			out = true;
		else
			printf("E065 Cannot create %s\n", path);
	}

	free(path);
	return out;
}


/* Loads an entire LDB sector into memory and returns a pointer
   (NULL if th sector does not exist) */
uint8_t *ldb_load_sector (struct ldb_table table, uint8_t *key) {

	FILE *ldb_sector = ldb_open(table, key, "r");
	if (!ldb_sector) return NULL;

	fseeko64(ldb_sector, 0, SEEK_END);
	uint64_t size = ftello64(ldb_sector);

	uint8_t *out = malloc(size);
	fseeko64(ldb_sector, 0, SEEK_SET);
	fread(out, 1, size, ldb_sector);
	fclose(ldb_sector);

	return out;
}

/* Reserves memory for storing a copy of an entire LDB sector
   (returns NULL if the source sector does not exist) */
uint8_t *ldb_load_new_sector (struct ldb_table table, uint8_t *key) {

	FILE *ldb_sector = ldb_open(table, key, "r");
	if (!ldb_sector) return NULL;

	fseeko64(ldb_sector, 0, SEEK_END);
	uint64_t size = ftello64(ldb_sector);
	fclose(ldb_sector);

	if (!size) return NULL;

	uint8_t *out = malloc(size);
	return out;
}

/* Create an empty data sector (empty map) */
void ldb_create_sector(char *sector_path)
{
	uint8_t *ldb_empty_map = calloc (ldb_sector_map_size, 1);

	FILE *ldb_map = fopen (sector_path, "w");
	fwrite(ldb_empty_map, ldb_sector_map_size, 1, ldb_map);
	fclose(ldb_map);

	free(ldb_empty_map);
}

/* Returns the sector path for a given table_path and key */
char *ldb_sector_path (struct ldb_table table, uint8_t *key, char *mode, bool tmp)
{
	/* Create table (directory) if it doesn't already exist */
	char table_path[512] = "\0";
	sprintf (table_path, "%s/%s/%s", ldb_root, table.db, table.table);

	if (!ldb_dir_exists (table_path))
	{
		printf("E063 Table %s does not exist\n", table_path);
		exit(EXIT_FAILURE);
	}

	char *sector_path = malloc(ldb_max_path + 1);
	if (table.tmp)
		sprintf (sector_path, "%s/%02x.tmp", table_path, key[0]);
	else
		sprintf (sector_path, "%s/%02x.ldb", table_path, key[0]);

	/* If opening a tmp table, we remove the file if it exists */
	if (ldb_file_exists(sector_path) && tmp) remove(sector_path);

	if (!ldb_file_exists(sector_path))
	{
		if (!strcmp(mode,"r"))
		{
			free(sector_path);
			return NULL;
		}
		ldb_create_sector(sector_path);
	}

	return sector_path;
}
