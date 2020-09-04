// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/command.c
 *
 * LDB Command line interface
 *
 * Copyright (C) 2018-2020 SCANOSS.COM
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

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "ldb.h"

void ldb_command_normalize(char *text)
{
	char *tmp = calloc(LDB_MAX_COMMAND_SIZE, 1);

	for (int i = 0; i < strlen(text); i++)
	{
		// Add interesting characters
		if (text[i] > ' ') tmp[strlen(tmp)] = text[i];
		else if (text[i] <= ' ')
		{
			// Add space only if not in the beginning and if previous char is not a space
			if (strlen(tmp))
				if (tmp[strlen(tmp)-1] != ' ') tmp[strlen(tmp)] = ' ';
		}
	}

	// Right trim
	if (strlen(tmp)) if (tmp[strlen(tmp)-1] == ' ') tmp[strlen(tmp)-1] = 0;

	strcpy(text, tmp);
	free(tmp);
}

/*	Checks command against list of known command and returns number
	of matched words and matched command (n)
	*/
commandtype ldb_syntax_check(char *command, int *command_nr, int *word_nr)
{
	int closest = 0;
	int hits;
	int command_words = ldb_word_count(command);

	// Recurse known commands
	for (int i = 0; i < ldb_commands_count; i++)
	{

		int known_words = ldb_word_count(ldb_commands[i]);
		int limit = known_words;
		if (command_words < limit) limit = command_words;
		hits = 0;

		// Compare words in given command against known command
		for (int j = 1; j <= limit; j++)
		{
			char *cword = ldb_extract_word(j, command);
			char *kword = ldb_extract_word(j, ldb_commands[i]);
			bool fulfilled = false;

			if (!strcmp(kword, "{hex}")) fulfilled = ldb_valid_hex(cword);
			else if (!strcmp(kword, "{ascii}")) fulfilled = ldb_valid_ascii(cword);
			else if (!strcmp(kword, cword)) fulfilled = true;
			free(cword);
			free(kword);

			if (!fulfilled) break;
			else if (j > hits)
			{
				closest = i;
				hits = j;
				*word_nr = hits;
				*command_nr = closest;
			}
		}
		if ((hits > 0) && (hits == known_words)) return true;
	}

	return false;
}

void ldb_command_collate(char *command)
{
	/* Lock DB */
	ldb_lock();

	/* Extract values from command */
	char *dbtable = ldb_extract_word(2, command);
	char *max_ln  = ldb_extract_word(4, command);
	int max = atoi(max_ln);
	free(max_ln);

	if (ldb_valid_table(dbtable))
	{
		/* Assembly ldb table structure */
		struct ldb_table ldbtable = ldb_read_cfg(dbtable);
		struct ldb_table tmptable = ldb_read_cfg(dbtable);
		tmptable.tmp = true;
		tmptable.key_ln = LDB_KEY_LN;

		if (ldbtable.rec_ln && ldbtable.rec_ln != max)
			printf("E076 Max record length should equal fixed record length (%d)\n", ldbtable.rec_ln);
		else if (max < ldbtable.key_ln)
			printf("E076 Max record length cannot be smaller than table key\n");
		else
			ldb_collate(ldbtable, tmptable, max, false);
	}

	/* Unlock DB */
	ldb_unlock ();

	/* Free memory */
	free(dbtable);
}

void ldb_command_merge(char *command)
{
	/* Lock DB */
	ldb_lock();

	/* Extract values from command */
	char *dbtable = ldb_extract_word(2, command);
	char *totable = ldb_extract_word(4, command);
	char *max_ln  = ldb_extract_word(6, command);
	int max = atoi(max_ln);
	free(max_ln);

	if (ldb_valid_table(dbtable))
	{
		/* Assembly ldb table structure */
		struct ldb_table ldbtable = ldb_read_cfg(dbtable);
		struct ldb_table outtable = ldb_read_cfg(totable);

		if (ldbtable.rec_ln && ldbtable.rec_ln != max)
			printf("E076 Max record length should equal fixed record length (%d)\n", ldbtable.rec_ln);
		else if (max < ldbtable.key_ln)
			printf("E076 Max record length cannot be smaller than table key\n");
		else if (ldbtable.key_ln != outtable.key_ln)
			printf("E076 Merge requires tables with equal key length\n");
		else if (ldbtable.rec_ln != outtable.rec_ln)
			printf("E076 Merge requires tables with equal record types\n");
		else
		{
			outtable.tmp = false;
			outtable.key_ln = LDB_KEY_LN;
			ldb_collate(ldbtable, outtable, max, true);
		}
	}

	/* Unlock DB */
	ldb_unlock ();

	/* Free memory */
	free(dbtable);
	free(totable);
}

void ldb_command_unlink_list(char *command)
{
	/* Extract values from command */
	char *dbtable = ldb_extract_word(4, command);
	char *key   = ldb_extract_word(6, command);
	uint8_t *keybin = malloc(LDB_MAX_NODE_LN);

	if (ldb_valid_table(dbtable))
	{

		/* Validate key and data */
		if (strlen(key) != 8) printf("E075 Key length must be 32 bits\n");

		else
		{
			/* Convert key to binary */
			ldb_hex_to_bin(key, keybin);

			/* Assembly ldb table structure */
			struct ldb_table ldbtable = ldb_read_cfg(dbtable);

			/* Open sector, wipe list pointer and close */
			FILE *sector;
			sector = ldb_open(ldbtable, keybin, "r+");
			ldb_list_unlink(sector, keybin);
			fclose(sector);
		}
	}

	/* Free memory */
	free(dbtable);
	free(key);
	free(keybin);
}


void ldb_command_insert(char *command, commandtype type)
{
	/* Extract values from command */
	char *dbtable = ldb_extract_word(3, command);	
	char *key   = ldb_extract_word(5, command);	
	char *data  = ldb_extract_word(7, command);	
	uint8_t *keybin = malloc(LDB_MAX_NODE_LN);
	uint8_t *databin = malloc(LDB_MAX_NODE_LN);
	uint32_t dataln;

	if (ldb_valid_table(dbtable))
	{

		/* Validate key and data */
		if (strlen(key) < 8) printf("E071 Key length cannot be less than 32 bits\n");

		else
		{
			/* Convert key and data to binary */
			ldb_hex_to_bin(key, keybin);
			if (type == INSERT_HEX) 
			{
				ldb_hex_to_bin(data, databin);
				dataln = (uint32_t) (strlen(data) / 2);
			}
			else dataln = strlen(data);

			/* Make room for recordset/record size */
			memmove(data+4, data, dataln);
			uint16_write((uint8_t *) data, (uint16_t) dataln + 2);
			uint16_write((uint8_t *) data+2, (uint16_t) dataln);
			dataln += 4;

			/* Assembly ldb table structure */
			struct ldb_table ldbtable = ldb_read_cfg(dbtable);

			/* Write record into ldb table */
			FILE *sector;
			sector = ldb_open(ldbtable, keybin, "r+");

			if (type == INSERT_HEX) 
				ldb_node_write(ldbtable, sector, keybin, databin, dataln, 0); // TODO, this 0 must come from cfg
			else
				ldb_node_write(ldbtable, sector, keybin, (uint8_t *) data, dataln, 0); // TODO Ditto

			fclose(sector);
		}
	}

	/* Free memory */
	free(dbtable);
	free(key);
	free(data);
	free(keybin);
	free(databin);
}

void ldb_command_create_table(char *command)
{
	char *tmp = ldb_extract_word(5, command);
	int keylen = atoi(tmp);
	tmp = ldb_extract_word(7, command);
	int reclen = atoi(tmp);
	free(tmp);

	char *dbtable = ldb_extract_word(3, command);
	char *table = dbtable + ldb_split_string(dbtable, '/');

	if (ldb_create_table(dbtable, table, keylen, reclen)) printf("OK\n");

	free(dbtable);
}

void ldb_command_select(char *command, bool ascii)
{

	/* Extract values from command */
	char *dbtable = ldb_extract_word(3, command);	
	char *key   = ldb_extract_word(5, command);
	uint8_t *keybin = malloc(LDB_MAX_NODE_LN);
	char *rs = malloc(LDB_MAX_NODE_DATA_LN);

	if (ldb_valid_table(dbtable))
	{
		/* Validate key */
		if (strlen(key) < 8) printf("E071 Key length cannot be less than 32 bits\n");

		else
		{
			/* Convert key to binary */
			ldb_hex_to_bin(key, keybin);
			int key_ln = (int) strlen(key) / 2;

			/* Assembly ldb table structure */
			struct ldb_table ldbtable = ldb_read_cfg(dbtable);

			/* Verify that provided key matches table key_ln (or main LDB_KEY_LEN) */
			if ((key_ln != ldbtable.key_ln) && (key_ln != LDB_KEY_LN))
				printf("E073 Provided key length is invalid\n");

			else if (ascii)
				ldb_fetch_recordset(NULL, ldbtable, keybin, (key_ln == 4), ldb_asciiprint, NULL);
			else
				ldb_fetch_recordset(NULL, ldbtable, keybin, (key_ln == 4), ldb_hexprint16, NULL);
		}
	}
	/* Free memory */
	free(dbtable);
	free(key);
	free(keybin);
	free(rs);
}

void ldb_command_create_database(char *command)
{
	char *database = ldb_extract_word(3, command);	
	char *path = malloc(LDB_MAX_PATH);
	sprintf(path, "%s/%s", ldb_root, database);

	if (!ldb_valid_name(database))
	{
		printf("E064 Invalid characters or name is too long\n");
	}
	else 
	{
		if (ldb_create_database(database)) printf("OK\n");
	}

	free(database);
}

void ldb_command_show_databases()
{
	DIR *dir;
	struct dirent *ent;
	if ((dir = opendir (ldb_root)) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if (ent->d_name[0] != '.')
			{
				char *path = malloc(LDB_MAX_PATH);
				sprintf(path, "%s/%s", ldb_root, ent->d_name);
				if (ldb_dir_exists(path)) printf ("%s\n", ent->d_name);
			}
		}
		closedir (dir);
	} else {
		printf("E070 Cannot open LDB root directory %s\n", ldb_root);
	}
}

void ldb_command_show_tables(char *command)
{

	char *dbname = ldb_extract_word(4, command);

	// Verify that db/table path is not too long
	if (strlen(dbname) + strlen(ldb_root) + 1 >= LDB_MAX_PATH)
		printf("E061 db/table name is too long\n");

	else if (!ldb_valid_name(dbname))
		printf("E064 Invalid characters or name is too long\n");

	else
	{	
		DIR *dir;
		struct dirent *ent;
		char *path = malloc(LDB_MAX_PATH);
		sprintf(path, "%s/%s", ldb_root, dbname);

		if ((dir = opendir(path)) != NULL) {
			while ((ent = readdir(dir)) != NULL) {
				if (ent->d_name[0] != '.')
				{
					char *tpath = malloc(LDB_MAX_PATH);
					sprintf(tpath, "%s/%s", path, ent->d_name);
					if (ldb_dir_exists(tpath)) printf("%s\n", ent->d_name); 
					free(tpath);
				}
			}
			closedir (dir);
		}
		else
		{
			printf("E072 Cannot access table %s\n", dbname);
		}

		free(path);
	}
	free(dbname);
}

/* Case insensitive string comparison */
bool stricmp(char *a, char *b)
{
	while (*a && *b) if (tolower(*a++) != tolower(*b++)) return false;
	return (*a == *b);
}

void print_record(uint8_t *ptr, int keyln, int hex)
{
	/* Print key */
	for (int i = 0; i < keyln; i++) printf("%02x", ptr[i]);

	/* Separator */
	printf(" ");

	/* Print data in hex */
	for (int i = 0; i < hex; i++) printf("%02x", ptr[keyln + i]);

	/* Separator */
	if (hex) printf(" ");

	/* Print remaining data */ 
	if (printf("%s\n", (char *) ptr + keyln + hex));
}


