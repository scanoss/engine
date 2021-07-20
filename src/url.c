// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/url.c
 *
 * URL handling functions
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
#include "match.h"
#include "report.h"
#include "debug.h"
#include "limits.h"
#include "util.h"
#include "snippets.h"
#include "decrypt.h"
#include "ignorelist.h"

bool handle_url_record(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
{
	if (!datalen && datalen >= MAX_PATH) return false;

	decrypt_data(raw_data, datalen, "url", key, subkey);

	uint8_t data[MAX_PATH] = "\0";
	memcpy(data, raw_data, datalen);
	data[datalen] = 0;

	match_data *matches = (match_data*) ptr;
	struct match_data match = match_init();

	/* Exit if we have enough matches */
	int total_matches = count_matches(matches);
	if (total_matches >= scan_limit) return true;

	match = fill_match(NULL, NULL, data);

	/* Save match component id */
	memcpy(match.url_md5, key, LDB_KEY_LN);
	memcpy(match.url_md5 + LDB_KEY_LN, subkey, subkey_ln);
	memcpy(match.file_md5, match.url_md5, MD5_LEN);

	add_match(-1, match, matches, true);

	return false;
}

/* Build a component URL from the provided PURL schema and actual URL */
bool build_main_url(match_data *match, char *schema, char *url, bool fixed)
{
	if (starts_with(match->purl, schema))
	{
		strcpy(match->main_url, url);
		if (!fixed) strcat(match->main_url, strstr(match->purl, "/"));
		return true;
	}
	return false;
}

/* Calculates a main project URL from the PURL */
void fill_main_url(match_data *match)
{
	/* URL translations */
	if (build_main_url(match, "pkg:github/", "https://github.com", false)) return;
	if (build_main_url(match, "pkg:npm/", "https://www.npmjs.com/package", false)) return;
	if (build_main_url(match, "pkg:npm/", "https://www.npmjs.com/package", false)) return;
	if (build_main_url(match, "pkg:maven/", "https://mvnrepository.com/artifact", false)) return;
	if (build_main_url(match, "pkg:pypi/", "https://pypi.org/project", false)) return;
	if (build_main_url(match, "pkg:nuget/", "https://www.nuget.org/packages", false)) return;
	if (build_main_url(match, "pkg:pypi/", "https://pypi.org/project", false)) return;
	if (build_main_url(match, "pkg:sourceforge/", "https://sourceforge.net/projects", false)) return;
	if (build_main_url(match, "pkg:gem/", "https://rubygems.org/gems/allowable", false)) return;
	if (build_main_url(match, "pkg:gitee/", "https://gitee.com", false)) return;
	if (build_main_url(match, "pkg:gitlab/", "https://gitlab.com", false)) return;

	/* Fixed, direct replacements */
	if (build_main_url(match, "pkg:kernel/", "https://www.kernel.org", true)) return;
	if (build_main_url(match, "pkg:angular/", "https://angular.io", true)) return;
}
