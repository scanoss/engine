// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/ldb.c
 *
 * LDB Database - A mapped linked-list database
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
#include "config.c"
#include "pointer.c"
#include "file.c"
#include "hex.c"  
#include "lock.c"
#include "node.c"
#include "recordset.c"
#include "sector.c"
#include "string.c"

const char LDB_VERSION[] = "2.02";

/* Global */
char ldb_root[] = "/var/lib/ldb";
char ldb_lock_path[] = "/dev/shm/ldb.lock";
const uint8_t  ldb_key_ln = 4; // Main LDB key:  32-bit
const uint8_t  ldb_ptr_ln = 5; // Node pointers: 40-bit
const uint64_t ldb_sector_map_size = 256 * 256 * 256 * 5;
const uint32_t ldb_max_recln  = 65535;
const uint32_t ldb_max_dataln  = 4 * 1048576; // Maximum length for a data record in a node (4Mb)
const uint32_t ldb_max_nodeln  = (256 * 256 * 18) - 1;
const uint32_t ldb_max_path = 1024; // Maximum length for a path
const uint32_t ldb_max_command_size = 64 * 1024; // Maximum length for an LDB command statement
int ldb_max_list_record_length = 1024; // Maximum record length in the sort list

char *ldb_commands[] = 
{
	"help",
	"create database {ascii}",
	"create table {ascii} keylen {ascii} reclen {ascii}",
	"show databases",
	"show tables from {ascii}",
	"insert into {ascii} key {hex} ascii {ascii}",
	"insert into {ascii} key {hex} hex {hex}",
	"select from {ascii} key {hex} ascii",
	"select from {ascii} key {hex}",
	"delete from {ascii} key {hex}",
	"drop database {ascii}",
	"drop table {ascii}",
	"version",
	"unlink list from {ascii} key {hex}",
	"sort table {ascii}",
	"dump table {ascii} hex {ascii}"
};
int ldb_commands_count = sizeof(ldb_commands) / sizeof(ldb_commands[0]);

void ldb_error (char *txt)
{
	fprintf (stdout, "%s\n", txt);
	exit (EXIT_FAILURE);
}

void ldb_version()
{
	printf("ldb-%s\n", LDB_VERSION);
}

