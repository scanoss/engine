// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * go-wrapper/snippets_wrapper.c
 *
 * Go wrapper implementation for SCANOSS snippet scanning
 *
 * Copyright (C) 2018-2021 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "snippets_wrapper.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../inc/scan.h"

// Redefine MAX_MULTIPLE_COMPONENTS to the value needed by the wrapper
#ifdef MAX_MULTIPLE_COMPONENTS
#undef MAX_MULTIPLE_COMPONENTS
#endif
#define MAX_MULTIPLE_COMPONENTS 30
#include "../inc/scanoss.h"
#include "../inc/match_list.h"
#include "../inc/debug.h"

extern match_t ldb_scan_snippets(scan_data_t *scan);
extern int matchmap_max_files;

// Only the wfp table is needed for scanning snippets
struct ldb_table oss_wfp;

// Minimal global variables for snippets
int min_match_hits = 10;
int min_match_lines = 10;
int range_tolerance = 5;
uint64_t engine_flags = 0;
char *extension = NULL;

bool snippets_wrapper_init(const char *oss_db_name, bool enable_debug) {
    debug_on = enable_debug;
    quiet = enable_debug;  // Use quiet mode for stderr output

    scanlog("snippets_wrapper_init START\n");

    // Initialize the wfp table
    char dbtable[MAX_ARGLN * 2];

    if (!oss_db_name) {
        oss_db_name = "oss";  // Default value
    }

    snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "wfp");

    scanlog("About to call ldb_read_cfg for: %s\n", dbtable);

    oss_wfp = ldb_read_cfg(dbtable);

    scanlog("ldb_read_cfg returned, keys=%u\n", oss_wfp.keys);

    // Verify if the table was initialized correctly
    if (oss_wfp.keys == 0) {
        fprintf(stderr, "Warning: LDB table 'wfp' not initialized properly\n");
        fprintf(stderr, "Make sure the LDB database exists at: %s\n", dbtable);
        return false;
    }

    scanlog("snippets_wrapper_init END\n");
    return true;
}

void snippets_wrapper_cleanup() {
    // For now, no specific cleanup is needed as the main engine doesn't have
    // a cleanup function. LDB handles cleanup automatically.
}

// Helper function for debugging - prints scan_data_t contents
void wrapper_debug_scan_data(scan_data_t *scan) {
    if (!scan) {
        scanlog("scan is NULL\n");
        return;
    }

    scanlog("scan_data_t:\n");
    scanlog("  MD5: %s\n", scan->source_md5);
    scanlog("  file_path: %s\n", scan->file_path ? scan->file_path : "NULL");
    scanlog("  hash_count: %u\n", scan->hash_count);
    scanlog("  total_lines: %d\n", scan->total_lines);
    scanlog("  file_size: %s\n", scan->file_size ? scan->file_size : "NULL");

    if (scan->hashes && scan->hash_count > 0) {
        fprintf(stderr, "  First 5 hashes: ");
        for (uint32_t i = 0; i < scan->hash_count && i < 5; i++) {
            fprintf(stderr, "%08x ", scan->hashes[i]);
        }
        fprintf(stderr, "\n");
    }

    if (scan->lines && scan->hash_count > 0) {
        fprintf(stderr, "  First 5 lines: ");
        for (uint32_t i = 0; i < scan->hash_count && i < 5; i++) {
            fprintf(stderr, "%u ", scan->lines[i]);
        }
        fprintf(stderr, "\n");
    }
}

wrapper_scan_result_t* snippets_wrapper_scan(wrapper_scan_input_t *input) {
    scanlog("snippets_wrapper_scan START\n");

    wrapper_scan_result_t *result = (wrapper_scan_result_t*)calloc(1, sizeof(wrapper_scan_result_t));
    if (!result) {
        scanlog("Failed to allocate result\n");
        return NULL;
    }

    scanlog("Result allocated, checking input\n");

    if (!input) {
        result->match_type = WRAPPER_MATCH_NONE;
        result->error_msg = strdup("Input is NULL");
        return result;
    }

    scanlog("Input OK, hash_count=%u\n", input->hash_count);

    if (!input->hashes || input->hash_count == 0) {
        result->match_type = WRAPPER_MATCH_NONE;
        result->error_msg = strdup("No hashes provided");
        return result;
    }

    if (!input->lines) {
        result->match_type = WRAPPER_MATCH_NONE;
        result->error_msg = strdup("No lines provided");
        return result;
    }

    scanlog("About to memset scan_data_t (size=%zu)\n", sizeof(scan_data_t));

    scan_data_t scan;
    memset(&scan, 0, sizeof(scan_data_t));

    scanlog("memset done\n");

    memcpy(scan.md5, input->md5, MD5_LEN);
    scan.file_path = input->file_path;
    scan.hashes = input->hashes;
    scan.lines = input->lines;
    scan.hash_count = input->hash_count;
    scan.total_lines = input->total_lines;
    scan.match_type = MATCH_NONE;

    // Initialize fields as done in scan_data_init
    scan.max_components_to_process = 1;
    scan.max_snippets_to_process = 1;
    scan.matches_list_array_index = 0;

    // Initialize file_size as done in scan_data_init
    scan.file_size = malloc(32);
    if (scan.file_size) {
        snprintf(scan.file_size, 32, "%d", input->total_lines);
    }

    // Convert MD5 to hex string
    for (int i = 0; i < MD5_LEN; i++) {
        sprintf(&scan.source_md5[i * 2], "%02x", input->md5[i]);
    }
    scan.source_md5[MD5_LEN * 2] = '\0';

    scanlog("Before calling ldb_scan_snippets\n");

    // Debug scan data if debug is enabled
    if (debug_on) {
        wrapper_debug_scan_data(&scan);
    }

    scanlog("About to call ldb_scan_snippets\n");

    match_t match_result = ldb_scan_snippets(&scan);

    scanlog("After ldb_scan_snippets, result=%d\n", match_result);

    switch(match_result) {
        case MATCH_NONE:
            result->match_type = WRAPPER_MATCH_NONE;
            break;
        case MATCH_FILE:
            result->match_type = WRAPPER_MATCH_FILE;
            break;
        case MATCH_SNIPPET:
            result->match_type = WRAPPER_MATCH_SNIPPET;
            break;
        case MATCH_BINARY:
            result->match_type = WRAPPER_MATCH_BINARY;
            break;
        default:
            result->match_type = WRAPPER_MATCH_NONE;
            result->error_msg = strdup("Unknown match type");
    }

    // Extract matching MD5s from matchmap
    if (match_result == MATCH_SNIPPET && scan.matchmap && scan.matchmap_size > 0) {
        result->matches = calloc(scan.matchmap_size, sizeof(wrapper_match_info_t));
        result->match_count = 0;

        for (uint32_t i = 0; i < scan.matchmap_size; i++) {
            if (scan.matchmap[i].hits > 0) {
                // Convert MD5 to hex string
                for (int j = 0; j < MD5_LEN; j++) {
                    sprintf(&result->matches[result->match_count].file_md5_hex[j * 2],
                            "%02x", scan.matchmap[i].md5[j]);
                }
                result->matches[result->match_count].file_md5_hex[MD5_LEN * 2] = '\0';
                result->matches[result->match_count].hits = scan.matchmap[i].hits;

                // Copy range information
                int ranges = scan.matchmap[i].ranges_number;
                result->matches[result->match_count].range_count = ranges;

                if (ranges > 0 && scan.matchmap[i].range) {
                    result->matches[result->match_count].range_from = calloc(ranges, sizeof(int));
                    result->matches[result->match_count].range_to = calloc(ranges, sizeof(int));
                    result->matches[result->match_count].oss_line = calloc(ranges, sizeof(int));

                    for (int r = 0; r < ranges; r++) {
                        result->matches[result->match_count].range_from[r] = scan.matchmap[i].range[r].from;
                        result->matches[result->match_count].range_to[r] = scan.matchmap[i].range[r].to;
                        result->matches[result->match_count].oss_line[r] = scan.matchmap[i].range[r].oss_line;
                    }
                }

                result->match_count++;
            }
        }

        // Sort matches by hits (descending)
        for (int i = 0; i < result->match_count - 1; i++) {
            for (int j = i + 1; j < result->match_count; j++) {
                if (result->matches[j].hits > result->matches[i].hits) {
                    // Swap
                    wrapper_match_info_t temp = result->matches[i];
                    result->matches[i] = result->matches[j];
                    result->matches[j] = temp;
                }
            }
        }
    }

    // Free allocated memory
    if (scan.file_size) {
        free(scan.file_size);
    }

    return result;
}

void snippets_wrapper_free_result(wrapper_scan_result_t *result) {
    if (result) {
        if (result->error_msg) {
            free(result->error_msg);
        }
        if (result->matches) {
            for (int i = 0; i < result->match_count; i++) {
                if (result->matches[i].range_from) free(result->matches[i].range_from);
                if (result->matches[i].range_to) free(result->matches[i].range_to);
                if (result->matches[i].oss_line) free(result->matches[i].oss_line);
            }
            free(result->matches);
        }
        free(result);
    }
}