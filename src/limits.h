// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/limits.h
 *
 * Definition of all limits within the application
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

/* Constants */
#define MD5_LEN 16
#define WFP_REC_LN 18

/* Limits */
#define MAX_ARGLN 512       // Max command line argument length
#define MAX_PATH 1024
#define MAX_MAP_RANGES 10
#define MAX_HASHES_READ 65535
#define MAX_FILE_SIZE (1024 * 1024 * 4)
#define MAX_QUERY_RESPONSE (1024 * 1024 * 8)
#define SLOW_QUERY_LIMIT_IN_USEC 2000000

/* Map record:[MD5(16)][hits(2)][range1(4)]....[rangeN(4)][lastwfp(4)] */
#define MAP_REC_LEN (16 + 2 + (MAX_MAP_RANGES * 6) + 4)

/* Snippets */
#define MAX_FILES 25000     // Max number of files evaluated in snippet matching
#define WFP_POPULARITY_THRESHOLD 2000  // wfp hash with more hits than this will be ignored. This should never be higher than MAX_FILES;
#define SKIP_SNIPPETS_IF_FILE_BIGGER (1024 * 1024 * 4)
#define SKIP_SNIPPETS_IF_STARTS_WITH (const char*[3]) {"{", "<?xml", "<html"}
#define MAX_SNIPPETS_SCANNED 2500

/* Variables */

/* During snippet scanning, when a wfp (with more than consecutive_threshold wfps) produces a score higher 
   than consecutive_score by consecutive_hits in a row, the scan will skip consecutive_jump snippets */
int scan_limit=10;

int consecutive_score = 4000;
int consecutive_hits = 4;
int consecutive_jump = 5;
int consecutive_threshold = 50;

int range_tolerance = 5;  // A maximum number of non-matched lines tolerated inside a matching range
int min_match_lines = 10; // Minimum number of lines matched for a match range to be acepted
