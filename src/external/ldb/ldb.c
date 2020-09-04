// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/ldb.c
 *
 * LDB Database - A mapped linked-list database
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
#include "collate.c"
#include "config.c"
#include "pointer.c"
#include "file.c"
#include "hex.c"  
#include "lock.c"
#include "node.c"
#include "recordset.c"
#include "sector.c"
#include "string.c"


/* Global */
char ldb_root[] = "/var/lib/ldb";
char ldb_lock_path[] = "/dev/shm/ldb.lock";
int ldb_cmp_width = 0;

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
	"collate {ascii} max {ascii}",
	"merge {ascii} into {ascii} max {ascii}",
	"version",
	"unlink list from {ascii} key {hex}"
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

