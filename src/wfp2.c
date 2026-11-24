// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/wfp2.c
 *
 * WFP2 (token-aware) fingerprint generation.
 *
 * Copyright (C) 2018-2025 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file wfp2.c
 * @brief Token-aware (wfp2) fingerprint generation.
 *
 * This is a faithful C port of the reference Go implementation
 * (scanoss-go pkg/fingerprint/wfp2, mirrored in wfp2_wrapper/internal) used by
 * go-minr to mine the wfp2 table. The pipeline is:
 *   DetectLanguage -> RemoveCommentsFromSource -> Normalizex -> HashSourceX
 * The normalization collapses identifiers (0xff) and consecutive types (0x00),
 * maps reserved words/punctuation to fixed byte codes, drops comments and
 * whitespace, and then winnows (GRAM 20 / WINDOW 40, CRC32C) the result.
 *
 * The output MUST match the mined fingerprints byte for byte; any divergence in
 * the tables or the algorithm makes the wfp2 snippet scan miss.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "crc32c.h"
#include "wfp2.h"

#define GRAM_WFP2 20
#define WINDOW_WFP2 40

/* ------------------------------------------------------------------ */
/* Reserved words / punctuation -> byte code. Generated from the Go
   elementsMap. Reserved codes: 0 (type marker), 0xff (other), plus the
   skipped 1,9,10,32,255. elementsMap is checked before typesMap. */
typedef struct { const char *key; uint8_t val; } wfp2_elem_t;

static wfp2_elem_t elements[] = {
	{"alias", 2}, {"alignas", 3}, {"alignof", 4}, {"and", 5}, {"as", 6}, {"asm", 7},
	{"assert", 8}, {"async", 11}, {"await", 12}, {"base", 13}, {"become", 14},
	{"begin", 15}, {"bindattr", 16}, {"bindingattr", 17}, {"bitand", 18}, {"bitor", 19},
	{"break", 20}, {"case", 21}, {"catch", 22}, {"cdecl", 23}, {"?", 24},
	{"checked", 25}, {"compl", 26}, {"concept", 27}, {"continue", 28}, {"crate", 29}, {"debugger", 30},
	{"declare", 31}, {"declspec", 33}, {"def", 34}, {"default", 35}, {"defer", 36},
	{"defined", 37}, {"del", 38}, {"delete", 39}, {"deriving", 40}, {"do", 41},
	{"@", 42}, {"dyn", 43}, {"dynamic", 44}, {"elif", 45}, {"else", 46}, {"elseif", 47}, {"elsif", 48},
	{"end", 49}, {"endfor", 50}, {"endforeach", 51}, {"endif", 52}, {"endswitch", 53}, {"endwhile", 54},
	{"eq", 55}, {"esac", 56}, {"except", 57}, {"explicit", 58}, {"export", 59},
	{"extends", 60}, {"fallthrough", 61}, {"far", 62}, {"fastcall", 63},
	{"feature", 64}, {"fi", 65}, {"finally", 66}, {"fixed", 67}, {"owns", 68}, {"fn", 69},
	{"for", 70}, {"foreach", 71}, {"forever", 72}, {"forsome", 73}, {"friend", 74}, {"from", 75},
	{"function", 76}, {"get", 77}, {"global", 78}, {"goto", 79}, {"has", 80}, {"id", 81},
	{"if", 82}, {"impl", 83}, {"implements", 84}, {"implicit", 85}, {"import", 86}, {"in", 87},
	{"include", 88}, {"infix", 89}, {"inherit", 90}, {"inout", 91},
	{"instanceof", 92}, {"spawn", 93}, {"deref", 94}, {"offsetof", 95},
	{"is", 96}, {"lambda", 97}, {"lateinit", 98},
	{"lazy", 99}, {"leave", 100}, {"let", 101}, {"local", 102}, {"lock", 103},
	{"loop", 104}, {"macro", 105}, {"match", 106}, {"me", 107}, {"module", 108},
	{"namespace", 109}, {"new", 110}, {"next", 111}, {"nil", 112}, {"no", 113},
	{"nocopy", 114}, {"none", 115}, {"nonlocal", 116}, {"not", 117},
	{"of", 118}, {"on", 119}, {"open", 120}, {"operator", 121},
	{"or", 122}, {"out", 123}, {"override", 124}, {"package", 125}, {"parallel", 126},
	{"params", 127}, {"partial", 128}, {"pass", 129}, {"past", 130}, {"print", 131},
	{"printf", 132}, {"procedure", 133}, {"pure", 134}, {"raise", 135}, {"rec", 136},
	{"receiver", 137}, {"redim", 138}, {"reified", 139},
	{"remove", 140}, {"repeat", 141}, {"require", 142}, {"required", 143}, {"resource", 144},
	{"resume", 145}, {"return", 146}, {"safe", 147}, {"sealed", 148},
	{"select", 149}, {"self", 150}, {"send", 151}, {"set", 152}, {"setparam", 153}, {"semaphore", 154},
	{"sizeof", 155}, {"stdcall", 156}, {"step", 157},
	{"sub", 158}, {"super", 159},
	{"suspend", 160}, {"switch", 161}, {"tailrec", 162}, {"then", 163},
	{"this", 164}, {"thread", 165}, {"throw", 166}, {"throws", 167}, {"to", 168},
	{"true", 169}, {"try", 170},
	{"unchecked", 171}, {"undef", 172},
	{"unless", 173}, {"unsized", 174},
	{"until", 175}, {"use", 176}, {"using", 177}, {"val", 178}, {"value", 179}, {"var", 180},
	{"wasm", 181},
	{"weak", 182}, {"when", 183}, {"where", 184}, {"while", 185}, {"with", 186}, {"xor", 187},
	{"/", 188}, {"yield", 189}, {"yieldto", 190}, {"subroutine", 191}, {"ensure", 192}, {"behind", 193}, {"exec", 194},
	{"!", 195}, {"\"", 196}, {"#", 197}, {"$", 198}, {"%", 199},
	{"&", 200}, {"'", 201}, {"(", 202}, {")", 203}, {"*", 204},
	{"+", 205}, {",", 206}, {"-", 207}, {".", 208},
	{":", 210}, {";", 211}, {"<", 212}, {"=", 213}, {">", 214},
	{"[", 217}, {"\\", 218}, {"]", 219},
	{"^", 220}, {"`", 221}, {"{", 222}, {"|", 223}, {"}", 224},
	{"~", 225},
};
#define N_ELEM (sizeof(elements) / sizeof(elements[0]))

/* Type keywords -> collapsed to a single 0x00 run. Generated from the Go
   typesMap. Entries containing non-alnum chars (e.g. "interface{}", "&str",
   "real*4", "comp-1") are kept for fidelity but never match a word token. */
static const char *types[] = {
	"char", "short", "int", "long", "float", "double", "void", "signed", "unsigned",
	"bool", "true", "false", "wchar", "const", "volatile", "static", "extern", "auto",
	"register", "inline", "mutable", "restrict", "constexpr", "consteval", "constinit",
	"noexcept", "class", "struct", "union", "enum", "interface", "typedef", "typename",
	"typealias", "type", "typeid", "typeof", "decltype", "trait", "protocol", "delegate",
	"event", "public", "private", "protected", "internal", "pub", "abstract", "virtual",
	"final", "sealed", "readonly", "synchronized", "transient", "strictfp", "native",
	"unsafe", "ptr", "ref", "byte", "boolean", "integer", "character", "string", "object",
	"sbyte", "ushort", "uint", "ulong", "decimal", "int16", "int32", "int64", "uint16",
	"uint32", "uint64", "single", "number", "undefined", "null", "symbol", "bigint",
	"str", "list", "dict", "tuple", "set", "frozenset", "bytes", "bytearray", "int8",
	"uint8", "float32", "float64", "complex64", "complex128", "rune", "uintptr",
	"interface{}", "chan", "func", "map", "slice", "i8", "i16", "i32", "i64", "i128",
	"isize", "u8", "u16", "u32", "u64", "u128", "usize", "f32", "f64", "&str", "vec",
	"option", "result", "box", "rc", "arc", "varchar", "real", "text", "blob", "numeric",
	"timestamp", "datetime", "date", "time", "smallint", "tinyint", "mediumint", "binary",
	"varbinary", "cardinal", "shortint", "longint", "comp", "currency", "extended",
	"real48", "ansichar", "widechar", "ansistring", "widestring", "shortstring", "pchar",
	"pwidechar", "logical", "complex", "real*4", "real*8", "integer*2", "integer*4",
	"pic", "picture", "comp-1", "comp-2", "comp-3", "comp-4", "comp-5", "packed-decimal",
	"display", "array", "dictionary", "shortarray", "intarray", "longarray", "floatarray",
	"doublearray", "booleanarray", "vhararray",
};
#define N_TYPE (sizeof(types) / sizeof(types[0]))

static int elem_cmp(const void *a, const void *b)
{
	return strcmp(((const wfp2_elem_t *)a)->key, ((const wfp2_elem_t *)b)->key);
}
static int str_cmp(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Tables are sorted once (lazily) so lookups can use bsearch. The engine scans
   files sequentially within a single process, so no locking is required. */
static bool tables_ready = false;
static void ensure_tables(void)
{
	if (tables_ready) return;
	qsort(elements, N_ELEM, sizeof(elements[0]), elem_cmp);
	qsort(types, N_TYPE, sizeof(types[0]), str_cmp);
	tables_ready = true;
}

/* Lookup a NUL-terminated token in the elements table. */
static bool elem_lookup(const char *word, uint8_t *out)
{
	wfp2_elem_t key = { word, 0 };
	wfp2_elem_t *r = bsearch(&key, elements, N_ELEM, sizeof(elements[0]), elem_cmp);
	if (r) { *out = r->val; return true; }
	return false;
}

/* True if the NUL-terminated token is a type keyword. */
static bool type_lookup(const char *word)
{
	const char *kp = word;
	return bsearch(&kp, types, N_TYPE, sizeof(types[0]), str_cmp) != NULL;
}

/* ------------------------------------------------------------------ */
/* Language detection and comment removal.
   Only the comment style actually matters downstream; languages whose comment
   patterns are identical (c/cpp/go/java/javascript) are interchangeable here. */

enum { L_NONE = 0, L_PYTHON, L_JAVA, L_GO, L_C, L_CPP, L_JS, L_RUBY, L_PHP };

static const char *kw_python[] = {"def", "import", "self", "print", "None", "True", "False", "elif", "except"};
static const char *kw_java[]   = {"public", "static", "void", "class", "implements", "extends", "null", "package"};
static const char *kw_go[]     = {"func", "package", "import", "defer", "chan", "go", "select", "map", "range"};
static const char *kw_c[]      = {"#include", "printf", "scanf", "malloc", "free", "NULL", "int", "char"};
static const char *kw_cpp[]    = {"#include", "cout", "cin", "std", "new", "delete", "namespace", "class"};
static const char *kw_js[]     = {"function", "var", "let", "const", "console", "undefined", "require", "export"};
static const char *kw_ruby[]   = {"def", "end", "puts", "require", "class", "module", "elsif", "unless"};
static const char *kw_php[]    = {"<?php", "echo", "var", "function", "$", "require", "include"};

/* Line / multiline comment delimiters, indexed by language id. */
typedef struct {
	int id;
	const char **kw;
	int nkw;
	const char *line[2];
	int nline;
	const char *mbeg[2];
	const char *mend[2];
	int nmulti;
} lang_def_t;

/* Fixed iteration order (ties resolved by first match, strict max). */
static lang_def_t langs[] = {
	{L_PYTHON, kw_python, 9, {"#", NULL}, 1, {"'''", "\"\"\""}, {"'''", "\"\"\""}, 2},
	{L_JAVA,   kw_java,   8, {"//", NULL}, 1, {"/*", NULL}, {"*/", NULL}, 1},
	{L_GO,     kw_go,     9, {"//", NULL}, 1, {"/*", NULL}, {"*/", NULL}, 1},
	{L_C,      kw_c,      8, {"//", NULL}, 1, {"/*", NULL}, {"*/", NULL}, 1},
	{L_CPP,    kw_cpp,    8, {"//", NULL}, 1, {"/*", NULL}, {"*/", NULL}, 1},
	{L_JS,     kw_js,     8, {"//", NULL}, 1, {"/*", NULL}, {"*/", NULL}, 1},
	{L_RUBY,   kw_ruby,   8, {"#", NULL}, 1, {"=begin", NULL}, {"=end", NULL}, 1},
	{L_PHP,    kw_php,    7, {"//", "#"}, 2, {"/*", NULL}, {"*/", NULL}, 1},
};
#define N_LANG (sizeof(langs) / sizeof(langs[0]))

static bool is_ws(unsigned char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

/* Index of needle (NUL-terminated) within s[0:n], or -1. */
static int idx_of(const char *s, int n, const char *needle)
{
	int nl = (int)strlen(needle);
	if (nl == 0 || nl > n) return -1;
	for (int i = 0; i + nl <= n; i++)
		if (memcmp(s + i, needle, nl) == 0) return i;
	return -1;
}

/* strings.TrimSpace: return the trimmed [*op, *op+*on) span of s[0:n]. */
static void trim_space(const char *s, int n, const char **op, int *on)
{
	int a = 0, b = n;
	while (a < b && is_ws((unsigned char)s[a])) a++;
	while (b > a && is_ws((unsigned char)s[b - 1])) b--;
	*op = s + a;
	*on = b - a;
}

/* strings.TrimRight(x, " \t"): reduce *n to drop trailing spaces/tabs. */
static void trim_right_ws(const char *s, int *n)
{
	int b = *n;
	while (b > 0 && (s[b - 1] == ' ' || s[b - 1] == '\t')) b--;
	*n = b;
}

/* strings.TrimLeft(x, " \t"). */
static void trim_left_ws(const char *s, int n, const char **op, int *on)
{
	int a = 0;
	while (a < n && (s[a] == ' ' || s[a] == '\t')) a++;
	*op = s + a;
	*on = n - a;
}

/*
 * DetectLanguage: split content on whitespace, and for every token count a hit
 * for each (language, keyword) whose keyword is a prefix of the token. Returns
 * the highest-scoring language id (L_NONE if nothing matched).
 *
 * WARNING (determinism): the reference Go implementation (go-minr / scanoss-go)
 * resolves ties via random map iteration, so for files where several languages
 * tie on score it is NON-deterministic, and the mined KB inherits that: the same
 * file can be normalized with different comment rules across mined files. This
 * port is deterministic (fixed order, first max wins), but for exact matching the
 * miner AND every scanner must share ONE deterministic tie rule and the KB be
 * re-mined with it. Until then, tie-files may match inconsistently.
 */
static int detect_language(const char *src, long n)
{
	int scores[N_LANG];
	memset(scores, 0, sizeof(scores));

	long i = 0;
	while (i < n)
	{
		while (i < n && is_ws((unsigned char)src[i])) i++;
		long start = i;
		while (i < n && !is_ws((unsigned char)src[i])) i++;
		int tlen = (int)(i - start);
		if (tlen <= 0) continue;
		const char *tok = src + start;

		for (unsigned int L = 0; L < N_LANG; L++)
		{
			for (int k = 0; k < langs[L].nkw; k++)
			{
				const char *kw = langs[L].kw[k];
				int kl = (int)strlen(kw);
				if (tlen >= kl && memcmp(tok, kw, kl) == 0)
					scores[L]++;
			}
		}
	}

	int best = -1, best_score = 0;
	for (unsigned int L = 0; L < N_LANG; L++)
	{
		if (scores[L] > best_score)
		{
			best_score = scores[L];
			best = (int)L;
		}
	}
	return best < 0 ? L_NONE : langs[best].id;
}

static lang_def_t *lang_by_id(int id)
{
	for (unsigned int L = 0; L < N_LANG; L++)
		if (langs[L].id == id) return &langs[L];
	return NULL;
}

/*
 * Process a single input line into out-buffer lb, mirroring the per-line logic
 * of RemoveCommentsFromSource. Returns the output line length; updates the
 * multiline-comment state across lines.
 */
static int strip_line(const char *line, int n, lang_def_t *L,
					   bool *in_multi, const char **multi_end, char *lb)
{
	if (*in_multi)
	{
		int idx = idx_of(line, n, *multi_end);
		if (idx >= 0)
		{
			*in_multi = false;
			int me = (int)strlen(*multi_end);
			const char *after = line + idx + me;
			int an = n - (idx + me);
			const char *ta; int tan;
			trim_space(after, an, &ta, &tan);
			if (tan > 0) { memcpy(lb, ta, tan); return tan; }
			return 0;
		}
		return 0; /* still inside the comment: emit an empty line */
	}

	/* Multiline comment start? */
	for (int m = 0; m < L->nmulti; m++)
	{
		const char *beg = L->mbeg[m];
		const char *end = L->mend[m];
		int beg_idx = idx_of(line, n, beg);
		if (beg_idx < 0) continue;

		int bl = (int)strlen(beg);
		const char *before = line;
		int before_n = beg_idx;
		trim_right_ws(before, &before_n);

		int search_start = beg_idx + bl;
		int rest_n = n - search_start;
		int end_idx = idx_of(line + search_start, rest_n, end);

		if (end_idx >= 0)
		{
			/* Comment opens and closes on the same line */
			int el = (int)strlen(end);
			const char *after = line + search_start + end_idx + el;
			int an = n - (search_start + end_idx + el);

			int out = 0;
			memcpy(lb, before, before_n);
			out = before_n;

			const char *ta; int tan;
			trim_space(after, an, &ta, &tan);
			if (tan > 0)
			{
				const char *la; int lan;
				trim_left_ws(after, an, &la, &lan);
				if (out > 0) { lb[out++] = ' '; memcpy(lb + out, la, lan); out += lan; }
				else { memcpy(lb, la, lan); out = lan; }
			}

			const char *tc; int tcn;
			trim_space(lb, out, &tc, &tcn);
			return tcn > 0 ? out : 0;
		}

		/* Comment continues on following lines */
		*in_multi = true;
		*multi_end = end;
		const char *tb; int tbn;
		trim_space(before, before_n, &tb, &tbn);
		if (tbn > 0) { memcpy(lb, before, before_n); return before_n; }
		return 0;
	}

	/* Line comment */
	const char *clean = line;
	int clean_n = n;
	for (int c = 0; c < L->nline; c++)
	{
		int idx = idx_of(line, n, L->line[c]);
		if (idx >= 0)
		{
			clean = line;
			clean_n = idx;
			trim_right_ws(clean, &clean_n);
			break;
		}
	}

	const char *tcl; int tcln;
	trim_space(clean, clean_n, &tcl, &tcln);
	if (tcln > 0) { memcpy(lb, clean, clean_n); return clean_n; }
	return 0;
}

/*
 * RemoveCommentsFromSource: strip comments line by line, preserving the line
 * count (removed lines become empty). Writes into out (caller-owned, must hold
 * at least 2*n+2 bytes). Returns the output length. If the language has no known
 * comment pattern, the source is copied unchanged.
 */
static long remove_comments(const char *src, long n, int lang_id, char *out)
{
	lang_def_t *L = lang_by_id(lang_id);
	if (!L)
	{
		memcpy(out, src, n);
		return n;
	}

	char *lb = malloc(n + 2);
	if (!lb)
	{
		memcpy(out, src, n);
		return n;
	}

	bool in_multi = false;
	const char *multi_end = "";
	long o = 0;
	long ls = 0;
	bool first = true;

	while (ls <= n)
	{
		long le = ls;
		while (le < n && src[le] != '\n') le++;
		int line_n = (int)(le - ls);

		if (!first) out[o++] = '\n';
		first = false;

		int outn = strip_line(src + ls, line_n, L, &in_multi, &multi_end, lb);
		if (outn > 0) { memcpy(out + o, lb, outn); o += outn; }

		if (le >= n) break;
		ls = le + 1;
	}

	free(lb);
	return o;
}

/* ------------------------------------------------------------------ */
/* Token-aware normalization (Normalizex). */

static unsigned char lc(unsigned char c)
{
	if (c >= 'A' && c <= 'Z') return c + 32;
	return c;
}
static bool is_alnum_(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

/*
 * Normalizex: lowercase, then per line emit one byte per token:
 *   reserved word / punctuation  -> its element code
 *   type keyword                 -> a single 0x00 for a run of consecutive types
 *   any other identifier         -> 0xff
 *   whitespace / unmapped char   -> dropped
 * Lines are preserved (separated by '\n'). Writes into out (>= n+2 bytes).
 * Returns the output length.
 */
static long normalizex(const char *in, long n, char *out)
{
	long o = 0;
	long ls = 0;
	bool first = true;

	while (ls <= n)
	{
		long le = ls;
		while (le < n && in[le] != '\n') le++;

		if (!first) out[o++] = '\n';
		first = false;

		bool last_was_type = false;
		long j = ls;
		while (j < le)
		{
			unsigned char rl = lc((unsigned char)in[j]);
			if (is_alnum_(rl))
			{
				char wbuf[256];
				int wl = 0;
				while (j < le && is_alnum_(lc((unsigned char)in[j])))
				{
					if (wl < (int)sizeof(wbuf) - 1) wbuf[wl++] = (char)lc((unsigned char)in[j]);
					j++;
				}
				wbuf[wl] = 0;

				uint8_t ev;
				if (elem_lookup(wbuf, &ev)) { out[o++] = (char)ev; last_was_type = false; }
				else if (type_lookup(wbuf)) { if (!last_was_type) out[o++] = 0x00; last_was_type = true; }
				else { out[o++] = (char)0xff; last_was_type = false; }
			}
			else
			{
				char cs[2] = { (char)rl, 0 };
				uint8_t ev;
				if (elem_lookup(cs, &ev)) out[o++] = (char)ev;
				last_was_type = false;
				j++;
			}
		}

		if (le >= n) break;
		ls = le + 1;
	}
	return o;
}

/* ------------------------------------------------------------------ */
/* Winnowing over the normalized byte stream (HashSourceX). */

static uint32_t min_hash(const uint32_t *h, int n)
{
	int idx = 0;
	for (int r = 0; r < n; r++)
		if (h[r] <= h[idx]) idx = r;
	return h[idx];
}

uint32_t winnowing_wfp2(char *src, long src_len, uint32_t *hashes, uint32_t *lines, long limit)
{
	if (!src || src_len <= 0 || limit <= 0) return 0;

	ensure_tables();

	int lang = detect_language(src, src_len);

	/* Comment removal, then normalization. Both outputs are <= 2*len. */
	char *no_com = malloc(2 * src_len + 2);
	char *norm = malloc(2 * src_len + 2);
	if (!no_com || !norm)
	{
		free(no_com);
		free(norm);
		return 0;
	}

	long nc_len = remove_comments(src, src_len, lang, no_com);
	long norm_len = normalizex(no_com, nc_len, norm);

	uint8_t window[GRAM_WFP2];
	int wlen = 0;
	uint32_t ghashes[WINDOW_WFP2];
	int hlen = 0;
	uint32_t last = 0;
	int cur_line = 1;
	uint32_t count = 0;

	for (long i = 0; i < norm_len; i++)
	{
		uint8_t ch = (uint8_t)norm[i];
		if (ch == '\n')
		{
			cur_line++;
			if (cur_line >= 0xffff) break;
			continue;
		}

		window[wlen++] = ch;
		if (wlen >= GRAM_WFP2)
		{
			ghashes[hlen++] = calc_crc32c((char *)window, GRAM_WFP2);
			if (hlen >= WINDOW_WFP2)
			{
				uint32_t a = min_hash(ghashes, WINDOW_WFP2);
				if (a != last)
				{
					last = a;
					uint8_t minbuf[4];
					minbuf[0] = (uint8_t)(a & 0xff);
					minbuf[1] = (uint8_t)((a >> 8) & 0xff);
					minbuf[2] = (uint8_t)((a >> 16) & 0xff);
					minbuf[3] = (uint8_t)((a >> 24) & 0xff);
					if ((long)count < limit)
					{
						hashes[count] = calc_crc32c((char *)minbuf, 4);
						lines[count] = (uint32_t)cur_line;
						count++;
					}
					else
					{
						break;
					}
				}
				/* hashes = hashes[1:WINDOW] */
				memmove(ghashes, ghashes + 1, (WINDOW_WFP2 - 1) * sizeof(uint32_t));
				hlen = WINDOW_WFP2 - 1;
			}
			/* window = window[1:GRAM] */
			memmove(window, window + 1, GRAM_WFP2 - 1);
			wlen = GRAM_WFP2 - 1;
		}
	}

	free(no_com);
	free(norm);
	return count;
}
