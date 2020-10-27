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
"xml",
"xpm",
"xsd",
"xul",
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
