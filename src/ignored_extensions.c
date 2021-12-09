// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/ignored_extensions.c
 *
 * Ignored file extensions
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

/**
  * @file ignored_extensions.c
  * @date 1 Jun 2020 
  * @brief Define the extensions to be excluded from the analysis.
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/ignored_extensions.c
  */

#include <stddef.h>

/** @brief File extensions to be skipped */
char *IGNORED_EXTENSIONS[] = {

	/* File extensions */
	".1", ".2", ".3", ".4", ".5", ".6", ".7", ".8", ".9", ".ac", ".adoc", ".am",
	".asc", ".asciidoc", ".bmp", ".build", ".cfg", ".chm", ".class", ".cmake",
	".cnf", ".conf", ".config", ".contributors", ".copying", ".crt", ".csproj",
	".css", ".csv", ".cvsignore", ".dat", ".data", ".db", ".doc", ".ds_store",
	".dtd", ".dts", ".dtsi", ".dump", ".eot", ".eps", ".geojson", ".gdoc", ".gif",
	".gitignore", ".glif", ".gmo", ".gradle", ".guess", ".hex", ".htm", ".html",
	".ico", ".in", ".inc", ".info", ".ini", ".ipynb", ".jpeg", ".jpg", ".json",
	".jsonld", ".log", ".m4", ".map", ".markdown", ".md", ".md5", ".meta", ".mk",
	".mxml", ".o", ".otf", ".out", ".pbtxt", ".pdf", ".pem", ".phtml", ".plist",
	".png", ".po", ".ppt", ".prefs", ".properties", ".pyc", ".qdoc", ".result",
	".rgb",".rst", ".rtf", ".scss", ".sha", ".sha1", ".sha2", ".sha256", ".sln",
	".spec", ".sql", ".sub", ".svg", ".svn-base", ".tab", ".template", ".test",
	".tex", ".tiff", ".toml", ".ttf", ".txt", ".utf-8", ".vim", ".wav", ".whl",
	".woff", ".xht", ".xhtml", ".xls", ".xml", ".xpm", ".xsd", ".xul", ".yaml",
	".yml", ".LAS",".adk",".asc",".cif",".cli",".cosmo",".deploy",
	".dfm",".dmm",".fa",".fasta",".fcb",".flm",".fna",".gbr",".gen",".gro",
	".hgtags",".hh",".ihex",".kp",".mpx",".pdb",".poly",".prn",".ps",".ref",
	".resx",".smp",".stg",".tfa",".tsv",".vcf",".vhd",".xy",".xyz",


	/* File endings */
	"-DOC", "CHANGELOG", "CONFIG", "COPYING", "COPYING.LIB", "LICENSE",
	"LICENSE.MD", "LICENSE.TXT", "LICENSES", "MAKEFILE", "NOTICE", "NOTICE",
	"README", "SWIFTDOC", "TEXIDOC", "TODO", "VERSION",

	/* End with null */
	NULL
};

/* Extensions that will skip snippet mining */
char *SKIP_MZ_EXTENSIONS[] = {".min.js", ".MF", ".base64", ".s", NULL};
