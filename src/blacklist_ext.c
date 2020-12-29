// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/blacklisted_ext.c
 *
 * Blacklisted file extensions
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

#include <stddef.h>

/* File extensions to be skipped */
char *BLACKLISTED_EXTENSIONS[] = {
	"1", "2", "3", "4", "5", "6", "7", "8", "9", "ac", "am", "bmp", "build",
	"cfg", "changelog", "chm", "class", "cmake", "cnf", "conf", "config",
	"contributors", "copying", "crt", "csproj", "css", "csv", "cvsignore",
	"dat", "data", "doc", "ds_store", "dtd", "dts", "dtsi", "dump", "eot",
	"eps", "geojson", "gif", "gitignore", "glif", "gmo", "gradle", "guess",
	"hex", "htm", "html", "ico", "in", "inc", "info", "ini", "ipynb",
	"jpeg", "jpg", "json", "jsonld", "license", "log", "m4", "makefile", "map",
	"markdown", "md", "md5", "meta", "mk", "mxml", "notice", "o", "otf", "out",
	"pbtxt", "pdf", "pem", "phtml", "png", "po", "ppt", "prefs", "properties",
	"pyc", "readme", "result", "rgb", "rst", "scss", "sha", "sha1", "sha2",
	"sha256", "sln", "spec", "sql", "sub", "svg", "svn-base", "tab", "template",
	"test", "tex", "tiff", "todo", "ttf", "txt", "utf-8", "version", "vim",
	"wav", "wfp", "whl", "woff", "xht", "xhtml", "xls", "xml", "xpm", "xsd",
	"xul", "yaml", "yml", NULL
};
