#ifndef __LDB_COMPAT_H
#define __LDB_COMPAT_H
/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * inc/ldb_compat.h
 *
 * Minimum LDB requirement for this engine release line.
 *
 * Copyright (C) 2018-2025 SCANOSS.COM
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

/**
 * @file ldb_compat.h
 * @date 2025
 * @brief Single source of truth for the LDB version this engine requires.
 *
 * The engine links libldb dynamically (-lldb), so the LDB it is compiled
 * against and the LDB it ends up loading at run time are not necessarily the
 * same build. Both are validated:
 *
 *   - build time: scripts/check_ldb_version.sh, driven from this header by
 *     the Makefile, reads LDB_VERSION out of the ldb.h the compiler resolves.
 *   - run time:   ldb_compat_check(), called from initialize_ldb_tables(),
 *     reads the version reported by the libldb.so actually loaded.
 *
 * Both checks derive their requirement from the macros below, so they cannot
 * drift apart. Do not hardcode a minimum version anywhere else.
 *
 * The four macros below are parsed by scripts/check_ldb_version.sh with a
 * plain `sed`, so keep the `#define NAME VALUE` spelling on a single line.
 */

#define LDB_REQUIRED_VERSION_MAJOR 5
#define LDB_REQUIRED_VERSION_MINOR 0
#define LDB_REQUIRED_VERSION_PATCH 0

/* Mandatory release-line suffix. The CRC64 line of LDB tags every release
 * with a "-crc64" suffix and carries it in LDB_VERSION, which is what tells a
 * CRC64-capable LDB apart from the MD5-only 4.x line. An MD5-only LDB may well
 * satisfy the version floor above and still be the wrong release line. */
#define LDB_REQUIRED_RELEASE_LINE "crc64"

#define LDB_COMPAT_STR_(x) #x
#define LDB_COMPAT_STR(x) LDB_COMPAT_STR_(x)

/** Human readable spelling of the minimum requirement, e.g. "5.0.0-crc64" */
#define LDB_REQUIRED_VERSION                 \
	LDB_COMPAT_STR(LDB_REQUIRED_VERSION_MAJOR) "." \
	LDB_COMPAT_STR(LDB_REQUIRED_VERSION_MINOR) "." \
	LDB_COMPAT_STR(LDB_REQUIRED_VERSION_PATCH) "-" LDB_REQUIRED_RELEASE_LINE

#include <stdbool.h>

bool ldb_compat_parse(const char *version, int *major, int *minor, int *patch, char *suffix, int suffix_ln);
void ldb_compat_check(void);

#endif
