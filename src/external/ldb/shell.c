// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/shell.c
 *
 * LDB Database simple shell
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

#include <ctype.h>
#include <dirent.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "ldb.h"
#include "command.c"

void help()
{
	printf("LDB stores information using single, 32-bit keys and single data records. Data records could be fixed in size (drastically footprint for large amounts of short, fixed-sized records). The LDB console accepts the following commands:\n");
	printf("\n");
	printf("create database DBNAME\n");
	printf("    Creates an empty database\n\n");
	printf("create table DBNAME/TABLENAME keylen N reclen N\n");
	printf("    Creates an empty table in the given database with\n");
	printf("    the specified key length (>= 4) and record length (0=variable)\n\n");
	printf("show databases\n");
	printf("    Lists databases\n\n");
	printf("show tables from DBNAME\n");
	printf("    Lists tables from given database\n\n");
	printf("insert into DBNAME/TABLENAME key KEY hex DATA\n");
	printf("    Inserts data (hex) into given db/table for the given hex key\n\n");
	printf("insert into DBNAME/TABLENAME key KEY ascii DATA\n");
	printf("    Inserts data (ASCII) into db/table for the given hex key\n\n");
	printf("select from DBNAME/TABLENAME key KEY\n");
	printf("    Retrieves all records from db/table for the given hex key (hexdump output)\n\n");
	printf("select from DBNAME/TABLENAME key KEY ascii\n");
	printf("    Retrieves all records from db/table for the given hex key (ascii output)\n\n");
	printf("delete KEY from DBNAME/TABLENAME\n");
	printf("    Deletes all records for the given hex key in the db/table\n\n");
	printf("collate DBNAME/TABLENAME max LENGTH\n");
	printf("    Collates all lists in a table, removing duplicates and records greater than LENGTH bytes\n\n");
	printf("merge DBNAME/TABLENAME1 into DBNAME/TABLENAME2 max LENGTH\n");
	printf("    Merges tables erasing tablename1 when done. Tables must have the same configuration\n\n");
	printf("unlink list from DBNAME/TABLENAME key KEY\n");
	printf("    Unlinks the given list (32-bit KEY) from the sector map\n\n");

}

bool execute(char *command)
{

	ldb_command_normalize(command);

	// Empty command does nothing
	if (!strlen(command)) return true;

	// QUIT quits
	if (!strcmp(command,"quit")) return false;

	// Parse other commands
	int command_nr = 0;
	int word_nr = 0;
	if (!ldb_syntax_check(command, &command_nr, &word_nr)) 
	{
		printf("E066 Syntax error\n");
		return true;
	}

	switch (command_nr)
	{
		case HELP:
			help();
			break;

		case SHOW_TABLES:
			ldb_command_show_tables(command);
			break;

		case SHOW_DATABASES:
			ldb_command_show_databases();
			break;

		case INSERT_ASCII:
			ldb_command_insert(command, command_nr);
			break;

		case INSERT_HEX:
			ldb_command_insert(command, command_nr);
			break;

		case SELECT:
			ldb_command_select(command, false);
			break;

		case SELECT_ASCII:
			ldb_command_select(command, true);
			break;

		case CREATE_DATABASE:
			ldb_command_create_database(command);
			break;

		case CREATE_TABLE:
			ldb_command_create_table(command);
			break;

		case UNLINK_LIST:
			ldb_command_unlink_list(command);
			break;

		case COLLATE:
			ldb_command_collate(command);
			break;

		case MERGE:
			ldb_command_merge(command);
			break;

		case VERSION:
			ldb_version();
			break;

		default:
			printf("E067 Command not implemented\n");
			break;
	}

	return true;
}


bool stdin_handle()
{

	char *command = NULL;
	size_t size = 0;

	if (!getline(&command, &size, stdin)) printf("Warning: cannot read STDIN\n");
	ldb_trim(command);

	bool stay = execute(command);

	free(command);
	return stay;
}

void welcome()
{
	printf("Welcome to LDB %s\n", LDB_VERSION);
	printf("Use help for a command list and quit for leaving this session\n\n"); 
}

void ldb_prompt()
{
	printf("ldb> ");
}

bool is_stdin_off()
{
	struct termios t;
	return (tcgetattr(STDIN_FILENO, &t) == 0);
}

int main()
{
	bool stdin_off = is_stdin_off();

	if (!ldb_check_root()) return EXIT_FAILURE;

	if (stdin_off) welcome();

	do if (stdin_off) ldb_prompt();
	while (stdin_handle() && stdin_off);

	return EXIT_SUCCESS;

}
