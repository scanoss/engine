// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/ignorelist.c
 *
 * Ignore/skipping functions
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

#include "ignorelist.h"
#include "ignored_extensions.h"

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

/* Compare if strings have the same ending */
bool ends_with(char *a, char *b)
{

	/* Obtain string lengths */
	int a_ln = strlen(a);
	int b_ln = strlen(b);
	int shortest = a_ln < b_ln ? a_ln : b_ln;

	/* Get pointers to last bytes */
	char *a_ptr = a + a_ln - 1;
	char *b_ptr = b + b_ln - 1;

	/* Walk the strings backwards */
	for (int i = 0; i < shortest; i++)
	{
		if (tolower(*a_ptr--) != tolower(*b_ptr--)) return false;
	}

	return true;
}

/* Returns true when the file "name" ends with a IGNORED_EXTENSIONS[] string */
bool ignored_extension(char *name)
{
	int i=0;
	while (IGNORED_EXTENSIONS[i])
		if (ends_with(IGNORED_EXTENSIONS[i++], name)) return true;

	return false;
}

/* Returns true when any element in IGNORED_PATHS is found in path */
bool unwanted_path(char *path)
{
	int i=0;
	while (IGNORED_PATHS[i])
		if (strstr(path,IGNORED_PATHS[i++]))
			return true;

	return false;
}

/* Case insensitive string comparison of starting of either string */
bool headicmp(char *a, char *b)
{
	while (*a && *b) if (tolower(*a++) != tolower(*b++)) return false;
	return true;
}

/* Returns true when src starts with any of the unwanted IGNORED_HEADER strings */
bool unwanted_header(char *src)
{
	int i=0;
	while (IGNORED_HEADERS[i])
	{
		if (headicmp(src,IGNORED_HEADERS[i]))
		{
			return true;
		}
		i++;
	}

	return false;
}

/* File paths to be skipped in results */
char *IGNORED_PATHS[] = {
	"/.eggs/",
	"/.git/",
	"/.github/",
	"/.svn/",
	"/.vscode/",
	"/__pycache__/",
	NULL
};

/* Files starting with any of these character sets will be skipped */
char *IGNORED_HEADERS[] =
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
