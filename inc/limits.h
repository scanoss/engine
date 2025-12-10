// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/limits.h
 *
 * Definition of all limits within the application
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
#include <stdint.h>

#ifndef __LIMITS_H
    #define __LIMITS_H
/* Constants */
#define MAX_COPYRIGHT 128

/* Limits */
#define MAX_ARGLN 512       // Max command line argument length
#define MAX_PATH 1024
#define MAX_HASHES_READ 65535
#define MAX_FILE_SIZE (1024 * 1024 * 4)
#define MAX_QUERY_RESPONSE (1024 * 1024 * 8)
#define SLOW_QUERY_LIMIT_IN_USEC 2000000
#define MAX_JSON_VALUE_LEN 4096
#define MAX_FILE_PATH 1024
#define FETCH_MAX_FILES_DEFAULT 12000
#define MIN_FILE_SIZE 256 // files below this size will be ignored
#define CRC_LIST_LEN 1024 // list of crc checksums to avoid metadata duplicates
#define SNIPPET_LINE_TOLERANCE 10

/* Snippets */
#define DEFAULT_MATCHMAP_FILES 10000     // Default number of files evaluated in snippet matching
#define MAX_MATCHMAP_FILES (DEFAULT_MATCHMAP_FILES * 10)     // Max number of files evaluated in snippet matching to prevent performance issues
#define MIN_LINES_COVERAGE 0.8
#define SKIP_SNIPPETS_IF_FILE_BIGGER (1024 * 1024 * 4)
#define MAX_SNIPPETS_SCANNED 2500

/* Variables */

extern int range_tolerance;  // A maximum number of non-matched lines tolerated inside a matching range
extern int min_match_lines; // Minimum number of lines matched for a match range to be acepted
extern int min_match_hits;  // Minimum number of snippet ID hits to produce a snippet match
extern int fetch_max_files; // Maximum number of files to fetch during component matching

#endif
