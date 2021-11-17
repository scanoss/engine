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
#include <stdlib.h>
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

/* Returns true when the file "name" ends with a SKIP_MZ_EXTENSIONS[] string */
bool skip_mz_extension(char *name)
{
	int i=0;
	while (SKIP_MZ_EXTENSIONS[i])
		if (ends_with(SKIP_MZ_EXTENSIONS[i++], name)) return true;

	return false;
}

/* Returns true when "ext" is among KNOWN_SRC_EXTENSIONS[] */
bool known_src_extension(char *ext)
{
	int i=0;
	while (KNOWN_SRC_EXTENSIONS[i])
		if (!stricmp(KNOWN_SRC_EXTENSIONS[i++], ext)) return true;

	return false;
}

/* Returns true when dotfile, dotdir or any element in IGNORED_PATHS is found in path */
bool unwanted_path(char *path)
{
	/* Path starts with a dot */
	if (*path == '.' && path[1] != '.' && path[1] != '/') return true;

	/* Path contains slash+dot+alnum */
	for (char *p = path; *p; p++)
		if (*p == '/')
			if (p[1]) if (p[1] == '.')
				if (isalnum(p[2])) return true;

	/* IGNORED_PATHS element is found in string */
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
	"/__pycache__/",
	"/__pypackages__",
	"/_yardoc/",
	"/eggs/",
	"/htmlcov/",
	"/nbbuild/",
	"/nbdist/",
	"/nbproject/",
	"/venv/",
	"/wheels/",
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

/* List of known source code extensions */
char *KNOWN_SRC_EXTENSIONS[] =
{
"4ge", "4gl", "4pk", "4th", "89x", "8xk", "a", "a2w", "a2x", "a3c", "a3x", "a51", "a5r", "a66", "a86", "a8s", "aah", "aar", "abap", "abc", "abl", "abs", "acgi", "acm", "action", "actionscript", "actproj", "actx", "acu", "ad2", "ada", "aem", "aep", "afb", "agc", "agi", "ago", "ahk", "ahtml", "aia", "aidl", "aiml", "airi", "ajm", "akp", "aks", "akt", "alan", "alg", "alx", "aml", "amos", "amw", "an", "androidproj", "ane", "anjuta", "apb", "apg", "aplt", "app", "appcache", "applescript", "applet", "appxmanifest", "appxsym", "appxupload", "aps", "apt", "arb", "armx", "arnoldc", "aro", "arq", "arscript", "art", "arxml", "ary", "as", "as3", "asax", "asbx", "asc", "ascx", "asf", "ash", "asi", "asic", "asm", "asmx", "asp", "asproj", "aspx", "asr", "ass", "asta", "astx", "asz", "atmn", "atmx", "atomsvc", "atp", "ats", "au3", "autoplay", "autosave", "avc", "ave", "avs", "avsi", "awd", "awk", "axb", "axd", "axe", "axs", "b", "b24", "b2d", "ba_", "bal", "bas", "bash", "bat", "bax", "bb", "bbc", "bbf", "bcc", "bcf", "bcp", "bdh", "bdsproj", "bdt", "beam", "bet", "beta", "bgm", "bhs", "bin_", "bml", "bmo", "bms", "borland", "bp", "bpo", "bpr", "bps", "brml", "brs", "brx", "bs2", "bsc", "bsh", "bsm", "bsml", "bsv", "bte", "btproj", "btq", "bufferedimage", "build", "builder", "buildpath", "bur", "bxb", "bxl", "bxml", "bxp", "bzs", "c", "c__", "c--", "c#", "c++", "c3p", "c86", "cal", "cap", "capfile", "cas", "cb", "cba", "cbl", "cbp", "cbs", "cc", "ccbjs", "ccp", "ccproj", "ccs", "ccxml", "cd", "cel", "cfi", "cfm", "cfml", "cfo", "cfs", "cg", "cgi", "cgvp", "cgx", "chd", "chef", "chh", "ck", "ckm", "cl", "cla", "class", "classdiagram", "classpath", "clips", "clj", "cljs", "clm", "clojure", "clp", "cls", "clw", "cmake", "cml", "cms", "cnt", "cob", "cobol", "cod", "coffee", "cola", "com_", "command", "common", "con", "configure", "confluence", "cord", "cos", "coverage", "coveragexml", "cp", "cpb", "cphd", "cplist", "cpp", "cpr", "cpy", "cpz", "cr", "cr2", "creole", "cs", "csb", "csc", "csdproj", "csh", "cshrc", "csi", "csm", "csml", "cson", "csp", "cspkg", "csproj", "csx", "ctl", "ctp", "cu", "cuh", "cx", "cxe", "cxl", "cxs", "cxx", "cya", "d", "d2j", "d4", "daemonscript", "datasource", "dba", "dbg", "dbmdl", "dbml", "dbo", "dbp", "dbpro", "dbproj", "dcf", "dcproj", "dcr", "dd", "ddp", "deb", "defi", "dep", "depend", "derp", "dev", "devpak", NULL
};

/* Add line length to the squareness ranking */
void increment_line_rank(int line_len, void *ptr)
{
	if (line_len <= 2) return;

	/* Walk rank and increment counter for line_len) */
	ranking *rank = ptr;
	for (int i = 0; i < 100; i++)
	{
		if (rank[i].length == 0 || rank[i].length == line_len)
		{
			rank[i].length = line_len;
			rank[i].counter++;
			break;
		}
	}
}

/* Select first item in the squareness ranking */
int select_first_in_ranking(void *ptr)
{
	int occurrences = 0;

	/* Select longer line from ranking */
	ranking *rank = ptr;
	for (int i = 0; i < 100; i++)
	{
		if (rank[i].counter > occurrences)
		{
			occurrences = rank[i].counter;
		}
	}

	return occurrences;
}

/* Determine if a file is over the desired squareness */
bool too_much_squareness(char *data)
{
	/* Declare/init variables */
	char *data_ptr = data;
	int line_len = 0;
	int line_counter = 1;
	bool unwanted = false;
	ranking *rank = calloc(100, sizeof(ranking));

	/* Walk data byte by byte */
	while (*data_ptr)
	{
		line_len++;

		if (*data_ptr == '\n')
		{
			increment_line_rank(line_len, rank);
			line_counter++;
			line_len = 0;
		}
		data_ptr++;
	}

	if (line_counter > 2)
	{
		/* Select first in ranking */
		int occurrences = select_first_in_ranking(rank);

		/* Print ID if conditions are matched */
		if (((100 * occurrences) / line_counter) > MAX_SQUARENESS && \
				line_counter > SQUARENESS_MIN_LINES)
		{
			unwanted = true;
		}
	}

	free(rank);
	return unwanted;
}
