// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/blacklist_ext.h
 *
 * Blacklisted extension list and search functions
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

char *BLACKLISTED_EXTENSIONS[] = {
"1",
"2",
"3",
"4",
"5",
"6",
"7",
"8",
"9",
"ac",
"am",
"build",
"cfg",
"chm",
"changelog",
"class",
"cmake",
"conf",
"contributors",
"copying",
"csproj",
"css",
"cvsignore",
"dat",
"dtd",
"geojson",
"gif",
"gitignore",
"glif",
"gmo",
"hex",
"html",
"htm",
"in",
"ini",
"ipynb",
"jpg",
"jpeg",
"json",
"license",
"m4",
"map",
"md",
"md5",
"mk",
"makefile",
"meta",
"notice",
"out",
"pdf",
"png",
"po",
"properties",
"readme",
"result",
"rst",
"sha",
"sha1",
"sha2",
"sha256",
"sln",
"spec",
"svg",
"svn-base",
"tab",
"template",
"test",
"tex",
"txt",
"utf-8",
"version",
"xhtml",
"xml",
"xpm",
"yaml",
"yml",
NULL
};

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

bool stricmp(char *a, char *b)
{
	while (*a && *b) if (tolower(*a++) != tolower(*b++)) return false;
	return (*a == *b);
}

/* Returns true when the file "name" contains a blacklisted code extension */
bool blacklisted(char *name)
{
	char *ext = extension(name);
    if (!ext) return true;
    if (!*ext) return true;

	int i=0;
	while (BLACKLISTED_EXTENSIONS[i]) 
		if (stricmp(BLACKLISTED_EXTENSIONS[i++], ext)) return true;

	return false;
}

bool unwanted_header(char *src)
{
       if (memcmp(src, "{", 1) == 0) return true;
       else if (memcmp(src, "<?xml", 5) == 0) return true;
       else if (memcmp(src, "<html", 5) == 0) return true;
       else if (memcmp(src, "<AC3D", 5) == 0) return true;
       return false;
}
