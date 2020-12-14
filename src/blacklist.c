#include <string.h>
#include <ctype.h>

#include "blacklist.h"

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

char *BLACKLISTED_PATHS[] = {
	"/third/",
	"/vendor/",
	"/external/",
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

/* File extensions to be skipped */
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
"bmp",
"build",
"cfg",
"chm",
"changelog",
"class",
"cmake",
"conf",
"config",
"contributors",
"copying",
"csproj",
"css",
"csv",
"cvsignore",
"dat",
"data",
"dtd",
"dts",
"dtsi",
"eps",
"geojson",
"gif",
"gitignore",
"glif",
"gmo",
"gradle",
"guess",
"hex",
"html",
"htm",
"ico",
"in",
"inc",
"info",
"ini",
"ipynb",
"jpg",
"jpeg",
"json",
"license",
"log",
"m4",
"map",
"markdown",
"md",
"md5",
"mk",
"makefile",
"meta",
"mxml",
"notice",
"out",
"pbtxt",
"pdf",
"pem",
"phtml",
"png",
"po",
"prefs",
"properties",
"readme",
"result",
"rst",
"scss",
"sha",
"sha1",
"sha2",
"sha256",
"sln",
"spec",
"sub",
"svg",
"svn-base",
"tab",
"template",
"test",
"tex",
"todo",
"txt",
"utf-8",
"version",
"vim",
"wav",
"xht",
"xhtml",
"xls",
"xml",
"xpm",
"xsd",
"xul",
"yaml",
"yml",
NULL
};

/* Ignore these words as path keywords */
char *IGNORE_KEYWORDS[] = 
{
	"archive",
	"arch",
	"assets",
	"backend",
	"beta",
	"beta1",
	"bridge",
	"boot",
	"build",
	"core",
	"documentation",
	"docs",
	"drivers",
	"files",
	"framework",
	"include",
	"javascripts",
	"lustre",
	"mach",
	"main",
	"manual",
	"master",
	"media",
	"net",
	"org",
	"platform",
	"plugins",
	"regex",
	"resources",
	"snippet",
	"src",
	"stable",
	"standard",
	"tools",
	"vendor",
	"web",
	"webapp",
	"workspace",
	NULL
};
