// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/ignorelist.h
 *
 * Ignoring/skipping data structures and routines
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

/* File paths to be skipped in results */
#ifndef __IGNORELIST_H
    #define __IGNORELIST_H
    
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

/* File squareness ranking */
typedef struct ranking
{
	int length;
	int counter;
} ranking;

/* Squareness check affects files over MIN_LINES
   with a bigger SQUARENESS percent */
#define SQUARENESS_MIN_LINES 500
#define MAX_SQUARENESS 70

extern char *IGNORED_PATHS[];
extern char *IGNORED_HEADERS[];
extern char *IGNORED_EXTENSIONS[];
extern char *IGNORE_KEYWORDS[];
extern char *KNOWN_SRC_EXTENSIONS[];

char *extension(char *path);
bool stricmp(char *a, char *b);
bool ignored_extension(char *name);
bool unwanted_path(char *path);
bool headicmp(char *a, char *b);
bool unwanted_header(char *src);
bool too_much_squareness(char *src);
bool skip_mz_extension(char *name);
bool known_src_extension(char *ext);

#endif
