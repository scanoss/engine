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
#define MATCH_ANALYZE_KEYWORD_LIMIT 10000 // Maximum number of keywords to be considered when analyzing matches

/* Snippets */
#define MAX_FILES 10000     // Max number of files evaluated in snippet matching
#define WFP_POPULARITY_THRESHOLD 5000  // wfp hash with more hits than this will be ignored. This should never be higher than MAX_FILES;
#define SKIP_SNIPPETS_IF_FILE_BIGGER (1024 * 1024 * 4)
#define SKIP_SNIPPETS_IF_STARTS_WITH (const char*[3]) {"{", "<?xml", "<html"}
#define MAX_SNIPPETS_SCANNED 2500

/* Variables */

/* During snippet scanning, when a wfp (with more than consecutive_threshold wfps) produces a score higher 
   than consecutive_score by consecutive_hits in a row, the scan will skip consecutive_jump snippets */
extern int consecutive_score;
extern int consecutive_hits;
extern int consecutive_jump;
extern int consecutive_threshold;

extern int range_tolerance;  // A maximum number of non-matched lines tolerated inside a matching range
extern int min_match_lines; // Minimum number of lines matched for a match range to be acepted
extern int min_match_hits;  // Minimum number of snippet ID hits to produce a snippet match

#endif
