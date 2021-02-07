// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/blacklist.c
 *
 * Blacklisting functions
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

#include <string.h>
#include <ctype.h>

#include "blacklist.h"
#include "blacklist_ext.h"

/* Returns a pointer to the file extension of "path" */
char *extension(char *path)
{
	char *dot   = strrchr(path, '.');
	char *slash = strrchr(path, '/');

	if (!dot && !slash) return NULL;
	if (dot > slash) return dot + 1;
	if (slash != path) return slash + 1;
	return NULL;
}

/* Case insensitive string comparison */
bool stricmp(char *a, char *b)
{
	while (*a && *b) if (tolower(*a++) != tolower(*b++)) return false;
	return (*a == *b);
}

/* Returns true when the file "name" contains a blacklisted code extension */
bool blacklisted_extension(char *name)
{
	char *ext = extension(name);
	if (!ext) return true;
	if (!*ext) return true;

	int i=0;
	while (BLACKLISTED_EXTENSIONS[i]) 
		if (stricmp(BLACKLISTED_EXTENSIONS[i++], ext))
			return true;

	return false;
}

/* Returns true when any element in BLACKLISTED_PATHS is found in path */
bool unwanted_path(char *path)
{
	int i=0;
	while (BLACKLISTED_PATHS[i])
		if (strstr(path,BLACKLISTED_PATHS[i++]))
			return true;

	return false;
}

/* Case insensitive string comparison of starting of either string */
bool headicmp(char *a, char *b)
{
	while (*a && *b) if (tolower(*a++) != tolower(*b++)) return false;
	return true;
}

/* Returns true when src starts with any of the unwanted BLACKLISTED_HEADER strings */
bool unwanted_header(char *src)
{
	int i=0;
	while (BLACKLISTED_HEADERS[i])
	{
		if (headicmp(src,BLACKLISTED_HEADERS[i]))
		{
			return true;
		}
		i++;
	}

	return false;
}

/* File paths to be skipped in results */
char *BLACKLISTED_PATHS[] = {
	"/.eggs/",
	"/.git/",
	"/.github/",
	"/.svn/",
	"/.vscode/",
	"/__pycache__/",
	NULL
};

/* Files starting with any of these character sets will be skipped */
char *BLACKLISTED_HEADERS[] =
{
	"{",
	"[",
	"<!doc",
	"<?xml",
	"<html",
	"<ac3d",
	NULL
};

/* Ignore these words as path keywords */
char *IGNORE_KEYWORDS[] = 
{
	"archive", "arch", "assets", "backend", "beta", "beta1", "bridge",
	"boot", "build", "core", "documentation", "docs", "drivers",
	"files", "framework", "include", "javascripts", "lustre", "mach",
	"main", "manual", "master", "media", "net", "org", "platform", "plugins",
	"regex", "resources", "snippet", "src", "stable", "standard", "tools",
	"vendor", "web", "webapp", "workspace", NULL
};
