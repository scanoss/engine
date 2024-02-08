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

/**
  * @file ignorelist.c
  * @date 1 Jun 2021 
  * @brief Contains the functions used for process the ignore extensions and paths list
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/ignorelist.c
  */

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "ignorelist.h"
#include "ignored_extensions.h"
#include "debug.h"

/**
 * @brief Returns a pointer to the file extension of "path"
 * @param path File pathh.
 * @return file extension string
 */
char *extension(char *path)
{
	char *dot   = strrchr(path, '.');
	char *slash = strrchr(path, '/');

	if (!dot && !slash) return NULL;
	if (dot > slash) return dot + 1;
	if (slash != path) return slash + 1;
	return NULL;
}

/**
 * @brief Case insensitive string comparison
 * @param a string a
 * @param b string b
 * @return True if are equals.
 */
bool stricmp(char *a, char *b)
{
	while (*a && *b) if (tolower(*a++) != tolower(*b++)) return false;
	return (*a == *b);
}

/**
 * @brief Compare if strings have the same ending
 * @param a string a
 * @param b string b
 * @return True if ends equal
 */
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

/**
 * @brief Returns true when the file "name" ends with a IGNORED_EXTENSIONS[] string
 * @param name file name
 * @return True if the file has an ignored extension.
 */
bool ignored_extension(char *name)
{
	int i=0;
	while (IGNORED_EXTENSIONS[i])
		if (ends_with(IGNORED_EXTENSIONS[i++], name)) 
		{
			scanlog("Component ignored by path extension: %s", name);
			return true;
		}

	return false;
}

/**
 * @brief Returns true when the file "name" ends with a SKIP_MZ_EXTENSIONS[] string
 * 
 * @param name file name 
 * @return true is the file has a skiped extension
 * @return false 
 */
bool skip_mz_extension(char *name)
{
	int i=0;
	while (SKIP_MZ_EXTENSIONS[i])
		if (ends_with(SKIP_MZ_EXTENSIONS[i++], name)) return true;

	return false;
}

/**
 * @brief Returns true when "ext" is among KNOWN_SRC_EXTENSIONS[]
 * 
 * @param ext extension
 * @return true is it is a know source extension
 */
bool known_src_extension(char *ext)
{
	int i=0;
	while (KNOWN_SRC_EXTENSIONS[i])
		if (stricmp(KNOWN_SRC_EXTENSIONS[i++], ext)) return true;

	return false;
}

/**
 * @brief Returns true when dotfile, dotdir or any element in IGNORED_PATHS is found in path
 * 
 * @param path file or dir path 
 * @return true if it is a dot file or dir.
 */
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

/**
 * @brief Case insensitive string comparison of starting of either string
 * @param a string a
 * @param b string b
 * @return true for equal
 */
bool headicmp(char *a, char *b)
{
	while (*a && *b) if (tolower(*a++) != tolower(*b++)) return false;
	return true;
}

/**
 * @brief Returns true when src starts with any of the unwanted IGNORED_HEADER strings
 * @param path //TODO
 * @return true if src starts with a unwanted header. False otherwise.
 */
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


/** @brief File paths to be skipped in results */
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

/** @brief Files starting with any of these character sets will be skipped */
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

/** @brief Ignore these words as path keywords */
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
"4ge", "4gl", "4pk", "4th", "89x", "8xk", "a", "a2w", "a2x", "a3c", "a3x", "a51", "a5r", "a66", "a86", "a8s", "aah", "aar", "abap", "abc", "abl", "abs", "acgi", "acm", "action", "actionscript", "actproj", "actx", "acu", "ad2", "ada", "aem", "aep", "afb", "agc", "agi", "ago", "ahk", "ahtml", "aia", "aidl", "aiml", "airi", "ajm", "akp", "aks", "akt", "alan", "alg", "alx", "aml", "amos", "amw", "an", "androidproj", "ane", "anjuta", "apb", "apg", "aplt", "app", "appcache", "applescript", "applet", "appxmanifest", "appxsym", "appxupload", "aps", "apt", "arb", "armx", "arnoldc", "aro", "arq", "arscript", "art", "arxml", "ary", "as", "as3", "asax", "asbx", "asc", "ascx", "asf", "ash", "asi", "asic", "asm", "asmx", "asp", "asproj", "aspx", "asr", "ass", "asta", "astx", "asz", "atmn", "atmx", "atomsvc", "atp", "ats", "au3", "autoplay", "autosave", "avc", "ave", "avs", "avsi", "awd", "awk", "axb", "axd", "axe", "axs", "b", "b24", "b2d", "ba_", "bal", "bas", "bash", "bat", "bax", "bb", "bbc", "bbf", "bcc", "bcf", "bcp", "bdh", "bdsproj", "bdt", "beam", "bet", "beta", "bgm", "bhs", "bin_", "bml", "bmo", "bms", "borland", "bp", "bpo", "bpr", "bps", "brml", "brs", "brx", "bs2", "bsc", "bsh", "bsm", "bsml", "bsv", "bte", "btproj", "btq", "bufferedimage", "build", "builder", "buildpath", "bur", "bxb", "bxl", "bxml", "bxp", "bzs", "c", "c__", "c--", "c#", "c++", "c3p", "c86", "cal", "cap", "capfile", "cas", "cb", "cba", "cbl", "cbp", "cbs", "cc", "ccbjs", "ccp", "ccproj", "ccs", "ccxml", "cd", "cel", "cfi", "cfm", "cfml", "cfo", "cfs", "cg", "cgi", "cgvp", "cgx", "chd", "chef", "chh", "ck", "ckm", "cl", "cla", "class", "classdiagram", "classpath", "clips", "clj", "cljs", "clm", "clojure", "clp", "cls", "clw", "cmake", "cml", "cms", "cnt", "cob", "cobol", "cod", "coffee", "cola", "com_", "command", "common", "con", "configure", "confluence", "cord", "cos", "coverage", "coveragexml", "cp", "cpb", "cphd", "cplist", "cpp", "cpr", "cpy", "cpz", "cr", "cr2", "creole", "cs", "csb", "csc", "csdproj", "csh", "cshrc", "csi", "csm", "csml", "cson", "csp", "cspkg", "csproj", "csx", "ctl", "ctp", "cu", "cuh", "cx", "cxe", "cxl", "cxs", "cxx", "cya", "d", "d2j", "d4", "daemonscript", "datasource", "dba", "dbg", "dbmdl", "dbml", "dbo", "dbp", "dbpro", "dbproj", "dcf", "dcproj", "dcr", "dd", "ddp", "deb", "defi", "dep", "depend", "derp", "dev", "devpak", "dfb", "dfd", "dfm", "dg", "dgml", "dgsl", "dht", "dhtml", "dia", "dic", "diff", "din", "dist", "dlg", "dmb", "dmc", "dml", "dms", "do", "dob", "docstates", "dor", "dot", "dpd", "dpk", "dpr", "dproj", "dqy", "drc", "dro", "ds", "dsa", "dsb", "dsd", "dse", "dso", "dsp", "dsq", "dsr", "dsym", "dt", "dtd", "dtml", "dto", "dts", "dtx", "dvb", "dwarf", "dwp", "dwt", "dxl", "e", "eaf", "ebc", "ebm", "ebs", "ebs2", "ebuild", "ebx", "ecore", "ecorediag", "edml", "eek", "egg-info", "ejs", "ekm", "el", "elc", "eld", "ema", "enml", "entitlements", "epl", "eqn", "es", "es6", "ev3p", "ew", "ex", "exe_", "exp", "exsd", "exu", "exv", "exw", "eze", "ezg", "f", "f03", "f40", "f77", "f90", "f95", "faces", "factorypath", "fas", "fasl", "fbp", "fbp6", "fbz6", "fcg", "fcgi", "fcmacro", "fdml", "fdo", "fdt", "ff", "fgb", "fgl", "fil", "fmb", "fmt", "fmx", "for", "form", "fountain", "fpc", "fpi", "frj", "frs", "frt", "fs", "fsb", "fscr", "fsf", "fsi", "fsproj", "fsx", "ftn", "fuc", "fus", "fwactionb", "fwx", "fxcproj", "fxh", "fxl", "fxml", "fzs", "g1m", "galaxy", "gbl", "gc3", "gch", "gcl", "gcode", "gdg", "geany", "gek", "gemfile", "generictest", "genmodel", "geojson", "gfa", "gfe", "ghc", "ghp", "git", "gla", "glade", "gld", "gls", "gml", "gnt", "go", "gobj", "goc", "gp", "gradle", "graphml", "graphmlz", "greenfoot", "groovy", "grxml", "gs", "gsb", "gsc", "gsk", "gss", "gst", "gus", "gv", "gvy", "gxl", "gyp", "gypi", "h", "h__", "h--", "h2o", "h6h", "haml", "has", "hay", "hbm", "hbs", "hbx", "hbz", "hc", "hcw", "hdf", "hei", "hh", "hhh", "hic", "history", "hkp", "hla", "hlsl", "hms", "hoic", "hom", "hpf", "hpp", "hrh", "hrl", "hs", "hsc", "hse", "hsm", "ht4", "htc", "htm", "html5", "htr", "hx", "hxa", "hxml", "hxp", "hxproj", "hxx", "hydra", "i", "iap", "ice", "idb", "ide", "idl", "idle", "ifp", "ig", "ii", "ijs", "ik", "il", "ilk", "image", "iml", "inc", "ino", "inp", "ins", "install", "io", "ipb", "ipch", "ipf", "ipp", "ipr", "ips", "ipy", "irb", "irbrc", "irc", "irobo", "is", "isa", "iss", "isu", "itcl", "itmx", "iwb", "ix3", "ixx", "j", "j3d", "jacl", "jad", "jade", "jak", "jardesc", "jav", "java", "javajet", "jbi", "jbp", "jcl", "jcm", "jcs", "jcw", "jdp", "jetinc", "jex", "jgc", "jgs", "ji", "jks", "jl", "jlc", "jmk", "jml", "jpage", "jpd", "jpx", "js", "jsa", "jsb", "jsc", "jscript", "jsdtscope", "jse", "jsf", "jsfl", "jsh", "jsm", "json", "jsonp", "jsp", "jss", "jsx", "jsxinc", "jtb", "ju", "judo", "jug", "jxl", "kbs", "kcl", "kd", "ked", "kex", "kit", "kix", "kl3", "kml", "kmt", "kodu", "komodo", "kon", "kpl", "ksc", "ksh", "kst", "kt", "kts", "kumac", "kv", "kx", "l", "lamp", "lap", "lasso", "lba", "lbi", "lbj", "lds", "ldz", "less", "lex", "lhs", "lib", "licenses", "licx", "liquid", "lis", "lisp", "litcoffee", "lml", "lmp", "lmv", "lng", "lnk", "lnp", "lnx", "lo", "loc", "login", "lol", "lols", "lp", "lpr", "lpx", "lrf", "lrs", "ls1", "ls3proj", "lsh", "lsp", "lss", "lst", "lsxtproj", "lua", "luac", "lub", "luca", "lxk", "m", "m2r", "m3", "m4", "m4x", "m51", "m6m", "mab", "mac", "magik", "mak", "make", "makefile", "maki", "mako", "maml", "map", "mash", "master", "mat", "matlab", "mb", "mbam", "mbas", "mbs", "mbtemmplate", "mc", "mcml", "mcp", "mcr", "mcw", "mdex", "mdf", "mdp", "mec", "mediawiki", "mel", "mex", "mf", "mfa", "mfcribbon-ms", "mfl", "mfps", "mg", "mhl", "mhm", "mi", "mingw", "mingw32", "mk", "mkb", "mke", "ml", "mli", "mln", "mls", "mlsxml", "mlv", "mlx", "mly", "mm", "mmb", "mmbas", "mmch", "mmh", "mmjs", "mnd", "mo", "moc", "mod", "module", "mom", "mpd", "mpm", "mpx", "mq4", "mq5", "mqt", "mrc", "mrd", "mrl", "mrm", "mrs", "ms", "msc", "mscr", "msdl", "msh1", "msh1xml", "msh2", "msh2xml", "msha", "msil", "msl", "msm", "mss", "mst", "msvc", "mtp", "mvba", "mvpl", "mw", "mwp", "mx", "mxe", "myapp", "mzp", "napj", "nas", "nbin", "nbk", "ncb", "ncx", "neko", "nes", "netboot", "nhs", "nj", "njk", "nk", "nlc", "nls", "nmk", "nnb", "nokogiri", "npi", "npl", "nrs", "nse", "nsi", "nspj", "nt", "nunit", "nupkg", "nvi", "nxc", "ob2", "obj", "obr", "ocb", "ocr", "odc", "odh", "odl", "ogl", "ogr", "ogs", "ogx", "okm", "opl", "oplm", "oppo", "opv", "opx", "oqy", "orl", "osas", "osg", "ow", "owd", "owl", "owx", "ox", "p", "p4a", "p5", "p6", "pag", "param", "pas", "pawn", "pb", "pba", "pbi", "pbl", "pbp", "pbxproj", "pc", "pcd", "pch", "pd", "pdb", "pde", "pdl", "pdml", "pdo", "pem", "perl", "pf?", "pf0", "pf1", "pf2", "pf3", "pf4", "pfa", "pfx", "pgm", "pgml", "ph", "phl", "php", "php1", "php2", "php3", "php4", "php5", "php6", "phpproj", "phps", "phpt", "phs", "phtml", "pickle", "pike", "pjt", "pjx", "pkb", "pkh", "pl", "pl1", "pl5", "pl6", "pl7", "playground", "plc", "pli", "plog", "pls", "plx", "pm", "pm5", "pm6", "pmod", "pmp", "pnproj", "po", "poc", "pod", "poix", "policy", "pom", "pou", "pp", "pp1", "ppa", "ppam", "ppml", "ppo", "pql", "pr7", "prg", "pri", "prl", "pro", "proto", "ps1", "ps2", "ps2xml", "psc1", "psc2", "psd1", "psf", "psl", "psm1", "psml", "pspscript", "psu", "ptl", "ptx", "ptxml", "pwo", "pxd", "pxml", "py", "pyc", "pym", "pyo", "pyt", "pyw", "pyx", "qac", "qdl", "qlc", "qlm", "qpf", "qry", "qs", "qsc", "qvs", "qx", "qxm", "r", "rake", "rakefile", "rb", "rbf", "rbp", "rbs", "rbt", "rbw", "rbx", "rc", "rc2", "rc3", "rcc", "rdf", "rdoc", "re", "reb", "rej", "res", "resjson", "resources", "resx", "rexx", "rfs", "rfx", "rgs", "rh", "rhtml", "rip", "rkt", "rml", "rmn", "rnw", "rob", "robo", "ror", "rpg", "rpj", "rpo", "rpp", "rpres", "rprofile", "rproj", "rptproj", "rpy", "rpyc", "rpym", "rqb", "rqc", "rqy", "rrc", "rrh", "rs", "rsl", "rsm", "rsp", "rss", "rtml", "rts", "rub", "rule", "run", "rvb", "rvt", "rws", "rxs", "s", "s2s", "s43", "s4e", "s5d", "saas", "sal", "sami", "sas", "sasf", "sass", "sax", "sb", "sbh", "sbml", "sbr", "sbs", "sc", "sca", "scala", "scar", "scb", "sce", "sci", "scm", "sconstruct", "scp", "scpt", "scptd", "scr", "script", "script editor", "scriptterminology", "scs", "scss", "sct", "scz", "sdef", "sdi", "sdl", "sdsb", "seam", "ser", "ses", "sf", "sfl", "sfm", "sfx", "sh", "shfb", "shfbproj", "shit", "simba", "simple", "sit", "sjc", "sjs", "skp", "sl", "slackbuild", "slim", "sln", "slt", "sltng", "sm", "sma", "smali", "sml", "smm", "smw", "smx", "snapx", "snippet", "sno", "snp", "spr", "spt", "spx", "sqlproj", "sqo", "src", "srz", "ss", "ssc", "ssi", "ssml", "ssq", "stl", "stm", "sts", "styl", "sus", "svc", "svn-base", "svo", "swg", "swift", "swt", "sxs", "sxt", "sxv", "synw-proj", "syp", "t", "tab", "targets", "tcl", "tcsh", "tcx", "tcz", "tdo", "tea", "tec", "texinfo", "text", "textile", "tgml", "thml", "thor", "thtml", "ti", "tik", "tikz", "tiprogram", "tk", "tkp", "tla", "tld", "tlh", "tli", "tmf", "tmh", "tmo", "toml", "tpl", "tplt", "tpm", "tpr", "tql", "tra", "trig", "triple-s", "trt", "tru", "ts0", "tsc", "tsq", "tst", "ttcn", "ttinclude", "ttl", "tur", "twig", "txl", "txml", "txx", "tzs", "ucb", "udf", "uem", "uih", "uit", "uix", "ulp", "ump", "usi", "usp", "uvproj", "uvprojx", "v", "v3s", "v4e", "vala", "vap", "vb", "vba", "vbe", "vbg", "vbhtml", "vbi", "vbp", "vbproj", "vbs", "vbscript", "vbw", "vbx", "vc", "vc15", "vc5", "vc6", "vc7", "vce", "vcp", "vcproj", "vcxproj", "vd", "vddproj", "vdp", "vdproj", "vfproj", "vgc", "vic", "vim", "vip", "viw", "vjp", "vls", "vlx", "vpc", "vpi", "vpl", "vps", "vrp", "vsixmanifest", "vsmacros", "vsprops", "vss", "vssscc", "vstemplate", "vtm", "vup", "vxml", "w", "wam", "was", "wax", "wbc", "wbf", "wbs", "wbt", "wch", "wcm", "wdi", "wdk", "wdl", "wdproj", "wdw", "wfs", "wiki", "win32manifest", "wis", "wli", "wml", "wmlc", "wmls", "wmlsc", "wmw", "wod", "wpj", "wpk", "wpm", "ws", "wsc", "wscript", "wsd", "wsdd", "wsdl", "wsf", "wsh", "wspd", "wxi", "wxl", "wxs", "wzs", "x", "xaml", "xamlx", "xap", "xba", "xbap", "xbl", "xblr", "xbs", "xcl", "xcodeproj", "xcp", "xda", "xfm", "xhtm", "xib", "xig", "xin", "xjb", "xje", "xla", "xlm", "xlm_", "xlv", "xme", "xml", "xml-log", "xmla", "xn", "xnf", "xojo_binary_project", "xoml", "xpb", "xpdl", "xpgt", "xproj", "xql", "xqr", "xr", "xrc", "xsc", "xsd", "xsl", "xslt", "xsql", "xtxt", "xui", "xul", "xv2", "xys", "yaml", "yml2", "ywl", "yxx", "yyp", "z", "zbi", "zcls", "zcode", "zero", "zfd", "zh_tw", "zpd", "zpk", "zpl", "zrx", "zs", "zsc", "zsh", "zts", "zws", NULL
};

/**
 * @brief  Add line length to the squareness ranking
 * @param line_le line length to add
 * @param prt pointer to ranqking
 */

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

/**
 * @brief  Select first item in the squareness ranking 
 * @param prt pointer to ranking struct
 */
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

/**
 * @brief  Determine if a file is over the desired squareness
 * @param data pointer to data for evaluation
 * @return return true for unwanted
 */
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
