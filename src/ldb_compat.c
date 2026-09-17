// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/ldb_compat.c
 *
 * Run time validation of the LDB library the engine is loaded against.
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
 * @file ldb_compat.c
 * @date 2025
 * @brief Validate, at run time, that the loaded libldb belongs to the release
 *        line this engine requires.
 *
 * libldb is linked dynamically, so the library resolved at load time may be a
 * different build from the one the engine was compiled against. The build time
 * counterpart of this check lives in scripts/check_ldb_version.sh; both derive
 * the requirement from inc/ldb_compat.h so they cannot diverge.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ldb_compat.h"
#include "scanoss.h"
#include "debug.h"

/**
 * @brief Parse an LDB version string into its semantic version components.
 *
 * Accepted spelling is MAJOR[.MINOR[.PATCH]][-SUFFIX], optionally preceded by
 * the "ldb-" prefix that the ldb shell prints. Missing MINOR/PATCH default to
 * zero. Anything after the first '-' is the release line suffix.
 *
 * @param version version string to parse
 * @param major output, major number
 * @param minor output, minor number
 * @param patch output, patch number
 * @param suffix output buffer for the release line suffix (empty if none)
 * @param suffix_ln size of the suffix output buffer
 * @return true if the numeric components could be parsed
 */
bool ldb_compat_parse(const char *version, int *major, int *minor, int *patch, char *suffix, int suffix_ln)
{
	*major = *minor = *patch = 0;
	if (suffix_ln > 0) *suffix = 0;

	if (!version) return false;

	/* Skip an optional "ldb-" prefix */
	if (!strncmp(version, "ldb-", 4)) version += 4;

	/* A version has to start with a digit */
	if (!isdigit((unsigned char) *version)) return false;

	int *component[3] = {major, minor, patch};
	int i = 0;
	const char *p = version;

	while (i < 3)
	{
		if (!isdigit((unsigned char) *p)) return false;

		long value = strtol(p, (char **) &p, 10);
		if (value < 0 || value > 1000000) return false;
		*component[i++] = (int) value;

		if (*p != '.' || i == 3) break;
		p++;
	}

	/* Anything left has to be the suffix, introduced by '-' */
	if (*p == '-')
	{
		p++;
		if (suffix_ln > 0)
		{
			strncpy(suffix, p, suffix_ln - 1);
			suffix[suffix_ln - 1] = 0;
		}
	}
	/* A trailing '\n' (or nothing at all) is fine, anything else is not */
	else if (*p && *p != '\n') return false;

	return true;
}

/**
 * @brief Abort the engine unless the loaded LDB satisfies inc/ldb_compat.h
 *
 * Reports "too old" and "wrong release line" as two distinct failures: they
 * call for different fixes on the user's side.
 */
void ldb_compat_check(void)
{
	char *ldb_ver = NULL;
	ldb_version(&ldb_ver);
	scanlog("ldb version: %s\n", ldb_ver ? ldb_ver : "(unknown)");

	int major = 0, minor = 0, patch = 0;
	char suffix[64] = "\0";

	if (!ldb_ver || !ldb_compat_parse(ldb_ver, &major, &minor, &patch, suffix, sizeof(suffix)))
	{
		fprintf(stderr,
			"ERROR: could not determine the version of the loaded LDB library (reported: %s).\n"
			"       SCANOSS engine %s requires LDB %s or later.\n",
			ldb_ver ? ldb_ver : "nothing", SCANOSS_VERSION, LDB_REQUIRED_VERSION);
		free(ldb_ver);
		exit(EXIT_FAILURE);
	}

	/* Numeric floor, compared component by component (never lexicographically:
	 * strcmp() would rank "5.10.0" below "5.9.0"). */
	long found = (long) major * 1000000 + (long) minor * 1000 + patch;
	long required = (long) LDB_REQUIRED_VERSION_MAJOR * 1000000 +
			(long) LDB_REQUIRED_VERSION_MINOR * 1000 + LDB_REQUIRED_VERSION_PATCH;

	if (found < required)
	{
		fprintf(stderr,
			"ERROR: the loaded LDB library is version %s, which is too old.\n"
			"       SCANOSS engine %s requires LDB %s or later.\n"
			"       Update LDB from the '%s' branch of https://github.com/scanoss/ldb\n",
			ldb_ver, SCANOSS_VERSION, LDB_REQUIRED_VERSION, LDB_REQUIRED_RELEASE_LINE);
		free(ldb_ver);
		exit(EXIT_FAILURE);
	}

	/* Release line. An MD5-only LDB can clear the numeric floor above and still
	 * be the wrong library: the table layout and the API differ. */
	if (strcmp(suffix, LDB_REQUIRED_RELEASE_LINE))
	{
		fprintf(stderr,
			"ERROR: the loaded LDB library is version %s, which belongs to the %s release line.\n"
			"       SCANOSS engine %s requires the '%s' release line of LDB (%s or later).\n"
			"       Install LDB from the '%s' branch of https://github.com/scanoss/ldb\n",
			ldb_ver, *suffix ? "wrong" : "MD5-only", SCANOSS_VERSION,
			LDB_REQUIRED_RELEASE_LINE, LDB_REQUIRED_VERSION, LDB_REQUIRED_RELEASE_LINE);
		free(ldb_ver);
		exit(EXIT_FAILURE);
	}

	free(ldb_ver);
}
