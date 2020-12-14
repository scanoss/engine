// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/blacklisted.h
 *
 * Blacklisted data structures and routines
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

/* File paths to be skipped in results */
#ifndef __BLACKLIST_H
    #define __BLACKLIST_H
    
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

extern char *BLACKLISTED_PATHS[];
extern char *BLACKLISTED_HEADERS[];
extern char *BLACKLISTED_EXTENSIONS[];
extern char *IGNORE_KEYWORDS[];

char *extension(char *path);
bool stricmp(char *a, char *b);
bool blacklisted_extension(char *name);
bool unwanted_path(char *path);
bool headicmp(char *a, char *b);
bool unwanted_header(char *src);



#endif