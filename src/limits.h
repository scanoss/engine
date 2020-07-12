// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/limits.h
 *
 * Definition of all limits within the application
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

#define MD5_LEN 16
#define MAX_ARGLN 512       // Max command line argument length
#define MAX_MAP_RANGES 10

/* Slow queries */
const int SLOW_QUERY_LIMIT_IN_USEC = 2000000;
const char SLOW_QUERY_LOG[] = "/tmp/scanoss_slow_query.log";

/* Skip snippets */
const int   SKIP_SNIPPETS_IF_FILE_BIGGER = 1024 * 1024 * 4;
const int   SKIP_SNIPPETS_IF_1ST_LINE_LONGER = 1000;
const char *SKIP_SNIPPETS_IF_STARTS_WITH[] = {"{", "<?xml", "<html"};

const uint32_t  wsi_per_line = 8;
const uint64_t  max_record_len     = 256 * 256;
const uint32_t  max_records        = 10000;
const uint32_t  max_lines          = 65536;
const uint32_t  max_files_per_line = 500;
const uint32_t  max_files          = 50000;
const uint32_t  max_query_response = 8 * 1048576;
const uint32_t  max_username       = 50;
const uint 	    max_variable_len   = 4096;
const int       max_field_name     = 50;
const int       max_snippets_scanned = 2500;
const int		max_path = 1024;
const int		max_file_size = 4 * 1048576;
const uint32_t wfp_popularity_threshold = 25000 ; // wfp hash with more hits than this will be ignored. This should never be higher than max_files;

const uint32_t detect_maxread = 10000; 	// Max # bytes to read from file or licenses
const uint32_t detect_threshold = 80;   // Match score threshold under which match is ignored
const uint32_t detect_minwords	 = 2;	// Min # words to group for comparison
const uint32_t detect_minbytes	 = 20;	// Min # bytes to group for comparison

/* During snippet scanning, when a wfp produces a score higher than consecutive_score by consecutive_hits in
   a row, the scan will skip consecutive_jump snippets */
int consecutive_score = 4000;
int consecutive_hits = 4;
int consecutive_jump = 5;

const int match_analyze_keyword_limit = 10000; // Maximum number of keywords to be considered when analyzing matches

int range_tolerance = 5;             // A maximum number of non-matched lines tolerated inside a matching range
int min_match_lines = 10;		 // Minimum number of lines matched for a match range to be acepted
