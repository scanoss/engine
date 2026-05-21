// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * inc/purl_scan.h
 *
 * SCANOSS Inventory Scanner
 *
 * Copyright (C) 2018-2024 SCANOSS.COM
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

#ifndef __PURL_SCAN_H
#define __PURL_SCAN_H

/**
 * @brief Resolve the purls and url hashes related to a file MD5.
 *
 * Looks up the given file MD5 in the KB (url and file tables) and prints, in
 * JSON, the unique purls associated with that file along with every url hash
 * (url_id) where the file was seen and the best (lowest) KB rank found for
 * each purl.
 *
 * @param file_md5_hex file MD5 in hex (32 chars)
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on invalid input
 */
int purl_scan(char *file_md5_hex);

/**
 * @brief Report the details of a single component identified by its url hash.
 *
 * Looks up the url record for the given url_hash (url_id) in the KB and
 * prints the component details in JSON, reusing the same rendering used in
 * regular scan reports (print_json_component).
 *
 * @param url_hash_hex url hash in hex (32 chars)
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on invalid input
 */
int component_scan(char *url_hash_hex);

/**
 * @brief Run a snippet-only scan whose WFP input comes from stdin.
 *
 * Reads a WFP block (same format used by `-w` scans) from stdin, runs the
 * snippet selection pipeline (no full-file lookup, no component resolution)
 * and prints a JSON report listing the file_md5 candidates grouped by snippet
 * region, together with their input/oss line ranges. Candidate cohort size is
 * controlled by the tolerance set via -T (match_list_tolerance_set).
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on invalid/empty input
 */
int snippet_scan_stdin(void);

/**
 * @brief Run a snippet-only scan whose WFP input is passed as a string.
 *
 * Same behavior as snippet_scan_stdin() but reads the WFP block from the
 * provided in-memory buffer. Used by `-S "<wfp>"` so callers (e.g. FlexAPI)
 * can pass the WFP directly as an argv value instead of piping it via stdin.
 *
 * @param wfp NUL-terminated buffer holding the WFP block
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on invalid/empty input
 */
int snippet_scan_string(const char *wfp);

#endif
