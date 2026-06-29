// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/purl_scan.c
 *
 * SCANOSS Inventory Scanner
 *
 * Copyright (C) 2018-2024 SCANOSS.COM
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
  * @file purl_scan.c
  * @brief Resolve the purls and url hashes related to a given file MD5.
  *
  * This implements the "-P <file_md5>" command: given a file MD5 it walks the
  * KB (url and file tables) and reports, in JSON, the unique purls associated
  * with that file, the url hashes (url_id) where the file was seen for each
  * purl and the best (lowest) KB rank found. It does not use the best-match
  * selection logic.
  */

#include <libgen.h>
#include "scanoss.h"
#include "debug.h"
#include "decrypt.h"
#include "parse.h"
#include "util.h"
#include "limits.h"
#include "component.h"
#include "report.h"
#include "url.h"
#include "license.h"
#include "health.h"
#include "dependency.h"
#include "copyright.h"
#include "vulnerability.h"
#include "scan.h"
#include "match.h"
#include "match_list.h"
#include "snippets.h"
#include "purl_scan.h"

/* Snippet-scan configuration globals (defined in main.c) */
extern int scan_max_snippets;
extern int scan_max_components;
extern bool scan_adjust_tolerance;
extern int scan_ranking_threshold;
extern int scan_min_match_hits;
extern int scan_min_match_lines;
extern int scan_range_tolerance;
extern bool scan_honor_file_extension;

/* Single purl entry: the purl, the set of url hashes seen and the best rank */
typedef struct purl_entry_t
{
	char *purl;
	char **url_hashes;
	int n_url_hashes;
	int url_hashes_cap;
	int rank;
	struct purl_entry_t *next;
} purl_entry_t;

/* Context passed through the ldb recordset handlers */
typedef struct purl_scan_ctx_t
{
	purl_entry_t *head;
	int count;
	uint32_t files_processed;
} purl_scan_ctx_t;

/* MD5 of the empty string, used as a sentinel in the file table */
static const uint8_t empty_string_md5[MD5_LEN] =
	{0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e};

/**
 * @brief Find an existing purl entry or create a new one.
 */
static purl_entry_t * purl_entry_get(purl_scan_ctx_t *ctx, const char *purl)
{
	for (purl_entry_t *e = ctx->head; e; e = e->next)
		if (!strcmp(e->purl, purl))
			return e;

	purl_entry_t *e = calloc(1, sizeof(*e));
	e->purl = strdup(purl);
	e->rank = COMPONENT_DEFAULT_RANK;
	e->next = ctx->head;
	ctx->head = e;
	ctx->count++;
	return e;
}

/**
 * @brief Add a url hash to a purl entry, ignoring duplicates and empty values.
 */
static void purl_entry_add_url_hash(purl_entry_t *e, const char *url_hash)
{
	if (!url_hash || !*url_hash)
		return;

	for (int i = 0; i < e->n_url_hashes; i++)
		if (!strcmp(e->url_hashes[i], url_hash))
			return;

	if (e->n_url_hashes >= e->url_hashes_cap)
	{
		e->url_hashes_cap = e->url_hashes_cap ? e->url_hashes_cap * 2 : 8;
		e->url_hashes = realloc(e->url_hashes, e->url_hashes_cap * sizeof(char *));
	}
	e->url_hashes[e->n_url_hashes++] = strdup(url_hash);
}

/* qsort comparators for deterministic output */
static int url_hash_cmp(const void *a, const void *b)
{
	return strcmp(*(const char **) a, *(const char **) b);
}

static int purl_entry_ptr_cmp(const void *a, const void *b)
{
	const purl_entry_t *ea = *(const purl_entry_t **) a;
	const purl_entry_t *eb = *(const purl_entry_t **) b;
	if (ea->rank != eb->rank)
		return ea->rank - eb->rank;
	return strcmp(ea->purl, eb->purl);
}

/**
 * @brief url table recordset handler. Extracts the purl and rank from the url
 * record and stores the url_id (= url_hash) under the matching purl entry.
 */
static bool handle_url_for_purls(struct ldb_table *table, uint8_t *key, uint8_t *subkey, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
{
	if (!datalen)
		return false;

	char *data = decrypt_data(raw_data, datalen, *table, key, subkey);
	if (!data)
		return false;

	char purl[MAX_FILE_PATH];
	char rank[MAX_FIELD_LN];
	extract_csv(purl, data, 6, sizeof(purl));
	extract_csv(rank, data, -1, sizeof(rank));
	free(data);

	if (!*purl)
		return false;

	purl_scan_ctx_t *ctx = (purl_scan_ctx_t *) ptr;
	purl_entry_t *e = purl_entry_get(ctx, purl);

	char url_hash_hex[MD5_LEN * 2 + 1];
	ldb_bin_to_hex(key, oss_url.key_ln, url_hash_hex);
	purl_entry_add_url_hash(e, url_hash_hex);

	if (*rank)
	{
		int r = atoi(rank);
		if (r > 0 && r < e->rank)
			e->rank = r;
	}

	return false;
}

/**
 * @brief file table recordset handler. Each record holds a 16 byte url id
 * followed by the (encrypted) path; for every url id we query the url table.
 */
static bool handle_file_for_purls(struct ldb_table *table, uint8_t *key, uint8_t *subkey, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
{
	/* Bound the amount of files processed (same limit used during matching) */
	if (iteration >= fetch_max_files)
	{
		scanlog("purl_scan: max file iterations reached: %d\n", fetch_max_files);
		return true;
	}

	if (datalen < MD5_LEN)
		return false;

	/* Skip records pointing to the empty string md5 */
	if (!memcmp(raw_data, empty_string_md5, MD5_LEN))
		return false;

	uint8_t url_id[MD5_LEN];
	memcpy(url_id, raw_data, MD5_LEN);

	ldb_fetch_recordset(NULL, oss_url, url_id, false, handle_url_for_purls, ptr);

	((purl_scan_ctx_t *) ptr)->files_processed++;
	return false;
}

int purl_scan(char *file_md5_hex)
{
	if (!file_md5_hex || !valid_hash(file_md5_hex, oss_file.key_ln))
	{
		fprintf(stdout, "Invalid file hash: %s\n", file_md5_hex ? file_md5_hex : "(null)");
		return EXIT_FAILURE;
	}

	uint8_t file_md5[MD5_LEN];
	ldb_hex_to_bin(file_md5_hex, oss_file.key_ln * 2, file_md5);

	purl_scan_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));

	ldb_fetch_recordset(NULL, oss_file, file_md5, false, handle_file_for_purls, &ctx);

	scanlog("purl_scan: %d unique purls found across %u files for %s\n", ctx.count, ctx.files_processed, file_md5_hex);

	/* Sort entries (rank asc, then purl) and url hashes for a deterministic output */
	purl_entry_t **sorted = NULL;
	if (ctx.count)
	{
		sorted = malloc(ctx.count * sizeof(purl_entry_t *));
		int i = 0;
		for (purl_entry_t *e = ctx.head; e; e = e->next)
		{
			if (e->n_url_hashes > 1)
				qsort(e->url_hashes, e->n_url_hashes, sizeof(char *), url_hash_cmp);
			sorted[i++] = e;
		}
		qsort(sorted, ctx.count, sizeof(purl_entry_t *), purl_entry_ptr_cmp);
	}

	if (!quiet)
	{
		printf("{\"file_md5\": \"%s\", \"matches\": [", file_md5_hex);
		for (int i = 0; i < ctx.count; i++)
		{
			purl_entry_t *e = sorted[i];
			if (i)
				printf(", ");
			printf("{\"purl\": \"%s\", \"url_hashes\": [", e->purl);
			for (int v = 0; v < e->n_url_hashes; v++)
			{
				if (v)
					printf(", ");
				printf("\"%s\"", e->url_hashes[v]);
			}
			printf("], \"rank\": %d}", e->rank);
		}
		printf("]}\n");
		fflush(stdout);
	}

	/* Cleanup */
	free(sorted);
	purl_entry_t *e = ctx.head;
	while (e)
	{
		purl_entry_t *next = e->next;
		for (int v = 0; v < e->n_url_hashes; v++)
			free(e->url_hashes[v]);
		free(e->url_hashes);
		free(e->purl);
		free(e);
		e = next;
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Resolve and report a single component identified by its url hash.
 * Emits one JSON object of the form {"url_hash": "...", "component": {...}}.
 */
static void component_scan_one(const char *url_hash_hex)
{
	uint8_t url_hash[MD5_LEN];
	ldb_hex_to_bin((char *) url_hash_hex, oss_url.key_ln * 2, url_hash);

	scanlog("component_scan_one: looking up url_hash=%s (declared_components=%p)\n",
		url_hash_hex, (void *) declared_components);

	component_data_t *component = NULL;
	int records = ldb_fetch_recordset(NULL, oss_url, url_hash, false, get_oldest_url, &component);
	scanlog("component_scan_one: url_hash=%s -> %d records, selected purl=%s identified=%d\n",
		url_hash_hex, records,
		(component && component->purls[0]) ? component->purls[0] : "(none)",
		component ? component->identified : -99);

	printf("{\"url_hash\": \"%s\", \"component\": ", url_hash_hex);
	if (!component)
	{
		printf("null");
	}
	else
	{
		/* Fill missing purl md5s (lazy step also done by print_json_component) */
		for (int i = 0; i < MAX_PURLS; i++)
		{
			if (component->purls[i] && !component->purls_md5[i])
			{
				component->purls_md5[i] = malloc(MD5_LEN);
				oss_purl.hash_calc((uint8_t *)component->purls[i], strlen(component->purls[i]), component->purls_md5[i]);
			}
		}

		/* print_licenses (and other enrichers) look up comp->file_md5_ref
		   unconditionally. We don't have a matched file in this mode, so
		   point it at the url_md5 to avoid a NULL deref; the lookup will
		   simply return no extra records. */
		if (!component->file_md5_ref)
			component->file_md5_ref = component->url_md5;

		fetch_related_purls(component);
		fill_main_url(component);

		printf("{");
		print_purl_array(component);

		printf("\"vendor\": \"%s\",", component->vendor ? component->vendor : "");
		printf("\"component\": \"%s\",", component->component ? component->component : "");

		char *version_clean = string_clean(component->version);
		printf("\"version\": \"%s\",", version_clean ? version_clean : "");

		char *latest_clean = string_clean(component->latest_version);
		printf("\"latest\": \"%s\",", latest_clean ? latest_clean : "");

		printf("\"url\": \"%s\",", component->main_url ? component->main_url : (component->url ? component->url : ""));
		printf("\"release_date\": \"%s\",", component->release_date ? component->release_date : "");

		/* The lookup is by url hash, so report the url basename as the file */
		char *file_field = NULL;
		if (component->url)
		{
			char *url_copy = strdup(component->url);
			file_field = strdup(basename(url_copy));
			free(url_copy);
		}
		printf("\"file\": \"%s\",", file_field ? file_field : "");
		free(file_field);

		printf("\"rank\": %d", component->rank);

		if (!(engine_flags & DISABLE_LICENSES))
		{
			print_licenses(component);
			if (component->license_text)
				printf(",%s", json_remove_invalid_char(component->license_text));
		}

		if (!(engine_flags & DISABLE_HEALTH))
		{
			if (!component->health_text)
				print_health(component);
			if (component->health_text)
				printf(",%s", json_remove_invalid_char(component->health_text));

			printf(",\"url_stats\":{");
			if (component->url_stats[0] > 0)
			{
				printf("\"total_files\":%d,"
					   "\"indexed_files\":%d,"
					   "\"source_files\":%d,"
					   "\"ignored_files\":%d,"
					   "\"package_size\":%d",
					   component->url_stats[0], component->url_stats[1], component->url_stats[2],
					   component->url_stats[3], component->url_stats[4]);
			}
			printf("}");
		}

		if (!(engine_flags & DISABLE_DEPENDENCIES))
		{
			if (!component->dependency_text)
				print_dependencies(component);
			if (component->dependency_text)
				printf(",%s", json_remove_invalid_char(component->dependency_text));
		}

		if (!(engine_flags & DISABLE_COPYRIGHTS))
		{
			print_copyrights(component);
			if (component->copyright_text)
				printf(",%s", component->copyright_text);
		}

		if (!(engine_flags & DISABLE_VULNERABILITIES))
		{
			print_vulnerabilities(component);
			if (component->vulnerabilities_text)
				printf(",%s", json_remove_invalid_char(component->vulnerabilities_text));
		}

		printf("}");
	}
	printf("}");

	if (component)
		component_data_free(component);
}

/**
 * @brief Resolve and report the details of one or more components identified
 * by url hash (url_id). Accepts a single hash or a comma-separated list.
 *
 * Output is always an array under the "results" key, one entry per input
 * hash: {"results": [{"url_hash": "...", "component": {...}}, ...]}.
 * Invalid hashes are skipped with a stderr warning.
 *
 * @param url_hash_list comma-separated url hashes in hex (32 chars each)
 * @return EXIT_SUCCESS if at least one valid hash was processed,
 *         EXIT_FAILURE if input is null/empty or no hash was valid
 */
int component_scan(char *url_hash_list)
{
	if (!url_hash_list || !*url_hash_list)
	{
		fprintf(stdout, "Invalid url hash list: %s\n", url_hash_list ? url_hash_list : "(null)");
		return EXIT_FAILURE;
	}

	char *input = strdup(url_hash_list);
	int emitted = 0;

	if (!quiet)
		printf("{\"results\": [");

	char *saveptr = NULL;
	for (char *tok = strtok_r(input, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr))
	{
		while (*tok == ' ' || *tok == '\t') tok++;
		char *end = tok + strlen(tok);
		while (end > tok && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n' || end[-1] == '\r'))
			*--end = '\0';

		if (!*tok)
			continue;

		if (!valid_hash(tok, oss_url.key_ln))
		{
			fprintf(stderr, "Invalid url hash, skipping: %s\n", tok);
			continue;
		}

		if (!quiet)
		{
			if (emitted)
				printf(", ");
			component_scan_one(tok);
		}
		emitted++;
	}

	if (!quiet)
	{
		printf("]}\n");
		fflush(stdout);
	}

	free(input);
	return emitted > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * @brief Snippet-only scan with WFP coming from an arbitrary FILE*. Emits
 * JSON listing the candidate file_md5s grouped by snippet region, with
 * input/oss line ranges, filtered by the cohort tolerance set via -T.
 */
static int snippet_scan_stream(FILE *in)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t lineln;

	scan_data_t *scan = NULL;
	char file_md5_hex[MD5_LEN * 2 + 1] = "";
	char file_path[MAX_FILE_PATH] = "";
	uint64_t file_size = 0;
	bool got_file = false;

	scanlog("--- SNIPPET SCAN ---\n");

	while ((lineln = getline(&line, &len, in)) != -1)
	{
		trim(line);

		if (!*line)
			continue;

		bool is_file = (memcmp(line, "file=", 5) == 0);
		bool is_fh2  = (memcmp(line, "fh2=",  4) == 0);
		bool is_hpsm = (memcmp(line, "hpsm=", 5) == 0);
		bool is_bin  = (memcmp(line, "bin=",  4) == 0);
		bool is_wfp  = (!is_file && !is_fh2 && !is_hpsm && !is_bin);

		/* Snippet-only mode: ignore hpsm/bin payloads */
		if (is_hpsm || is_bin)
			continue;

		if (is_file)
		{
			if (got_file)
			{
				fprintf(stderr, "snippet-scan: multiple file= entries received, ignoring extras\n");
				continue;
			}

			const int tagln = 5;
			if (strlen(line) < (size_t)(tagln + oss_file.key_ln * 2 + 1))
			{
				fprintf(stderr, "snippet-scan: malformed file= line\n");
				free(line);
				return EXIT_FAILURE;
			}

			char *hexmd5 = strndup(line + tagln, oss_file.key_ln * 2);
			if (!hexmd5 || !valid_hash(hexmd5, oss_file.key_ln))
			{
				fprintf(stderr, "snippet-scan: invalid md5 in file= line\n");
				free(hexmd5);
				free(line);
				return EXIT_FAILURE;
			}
			strcpy(file_md5_hex, hexmd5);
			free(hexmd5);

			uint8_t *rec = (uint8_t *) strdup(line + tagln + oss_file.key_ln * 2 + 1);
			char *target_path = field_n(2, (char *) rec);
			if (!target_path)
			{
				fprintf(stderr, "snippet-scan: malformed file= line (missing path)\n");
				free(rec);
				free(line);
				return EXIT_FAILURE;
			}

			strncpy(file_path, target_path, sizeof(file_path) - 1);
			file_path[sizeof(file_path) - 1] = '\0';

			char size_field[MAX_FIELD_LN] = "0";
			extract_csv(size_field, (char *) rec, 1, sizeof(size_field));
			file_size = strtoull(size_field, NULL, 10);

			scan = scan_data_init(file_path,
			                      scan_max_snippets,
			                      scan_max_components,
			                      scan_adjust_tolerance,
			                      scan_ranking_threshold,
			                      scan_min_match_hits,
			                      scan_min_match_lines,
			                      scan_range_tolerance,
			                      scan_honor_file_extension);
			scan->preload = true;
			/* The input WFP has no reliable extension, and oss_file lookup
			   inside snippet_extension_discard would discard valid hits. */
			scan->snippet_honor_file_extension = false;
			/* scan->file_size is a fixed 32-byte buffer; write the parsed
			   numeric value, which always fits, instead of the raw field */
			snprintf(scan->file_size, 32, "%llu", (unsigned long long) file_size);
			ldb_hex_to_bin(file_md5_hex, oss_file.key_ln * 2, scan->md5);
			strcpy(scan->source_md5, file_md5_hex);
			free(rec);
			got_file = true;
			continue;
		}

		if (is_fh2 && scan && strlen(line) == oss_file.key_ln*2 + 4)
		{
			ldb_hex_to_bin(&line[4], oss_file.key_ln*2, scan->md5_fh2);
			scan->windows_line_endings = true;
			continue;
		}

		if (is_wfp && scan && (scan->hash_count < MAX_HASHES_READ))
		{
			int line_ln = strlen(line);
			for (int e = 0; e < line_ln; e++)
				if (line[e] == '=' || line[e] == ',') line[e] = 0;

			int line_nr = atoi(line);
			char *hexhash = line + strlen(line) + 1;

			while (*hexhash)
			{
				ldb_hex_to_bin(hexhash, 8, (uint8_t *) &scan->hashes[scan->hash_count]);
				uint32_reverse((uint8_t *) &scan->hashes[scan->hash_count]);
				scan->lines[scan->hash_count] = line_nr;
				hexhash += strlen(hexhash) + 1;
				scan->hash_count++;
				if (scan->hash_count >= MAX_HASHES_READ)
					break;
			}
		}
	}
	free(line);

	if (!scan)
	{
		fprintf(stderr, "snippet-scan: no file= entry in WFP input\n");
		return EXIT_FAILURE;
	}

	if (scan->hash_count == 0)
	{
		fprintf(stderr, "snippet-scan: no WFP hashes in WFP input\n");
		scan_data_free(scan);
		return EXIT_FAILURE;
	}

	scan->total_lines = scan->lines[scan->hash_count - 1];
	scan->timer = microseconds_now();
	scan->match_type = ldb_scan_snippets(scan);

	if (scan->match_type != MATCH_NONE)
		biggest_snippet(scan);

	if (!quiet)
	{
		char *escaped_path = scape_slashes(file_path);
		printf("{");
		printf("\"file_md5\":\"%s\",", file_md5_hex);
		printf("\"file_path\":\"%s\",", escaped_path ? escaped_path : "");
		printf("\"file_size\":%llu,", (unsigned long long) file_size);
		printf("\"total_lines\":%d,", scan->total_lines);
		printf("\"tolerance_pct\":%.1f,", match_list_tolerance_get());
		printf("\"snippet_groups\":[");

		bool first_group = true;
		for (int g = 0; g < scan->matches_list_array_index; g++)
		{
			match_list_t *list = scan->matches_list_array[g];
			if (!list || !list->items)
				continue;

			if (!first_group)
				printf(",");
			first_group = false;

			printf("{\"group_index\":%d,\"candidates\":[", g);
			bool first_cand = true;
			for (struct entry *np = list->headp.lh_first; np != NULL; np = np->entries.le_next)
			{
				match_data_t *m = np->match;
				if (!m)
					continue;

				char md5_hex[MD5_LEN * 2 + 1];
				ldb_bin_to_hex(m->file_md5, oss_file.key_ln, md5_hex);

				if (!first_cand)
					printf(",");
				first_cand = false;

				printf("{\"file_md5\":\"%s\",",    md5_hex);
				printf("\"hits\":%d,",              m->hits);
				printf("\"lines_matched\":%d,",     m->lines_matched);
				printf("\"matched_percent\":%d,",   m->matched_percent);
				printf("\"input_line_ranges\":\"%s\",", m->line_ranges ? m->line_ranges : "");
				printf("\"oss_line_ranges\":\"%s\"",    m->oss_ranges ? m->oss_ranges : "");
				printf("}");
			}
			printf("]}");
		}
		printf("]}\n");
		fflush(stdout);
		free(escaped_path);
	}

	scan_data_free(scan);
	return EXIT_SUCCESS;
}

int snippet_scan_stdin(void)
{
	return snippet_scan_stream(stdin);
}

int snippet_scan_string(const char *wfp)
{
	if (!wfp || !*wfp)
	{
		fprintf(stderr, "snippet-scan: empty WFP argument\n");
		return EXIT_FAILURE;
	}

	FILE *in = fmemopen((void *) wfp, strlen(wfp), "r");
	if (!in)
	{
		fprintf(stderr, "snippet-scan: failed to open WFP argument as stream\n");
		return EXIT_FAILURE;
	}

	int rc = snippet_scan_stream(in);
	fclose(in);
	return rc;
}
