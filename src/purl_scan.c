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
  * @brief Resolve the purls and versions related to a given file MD5.
  *
  * This implements the "-P <file_md5>" command: given a file MD5 it walks the
  * KB (url and file tables) and reports, in JSON, the unique purls associated
  * with that file, the versions where the file was seen for each purl and the
  * best (lowest) KB rank found. It does not use the best-match selection logic.
  */

#include "scanoss.h"
#include "debug.h"
#include "decrypt.h"
#include "parse.h"
#include "util.h"
#include "limits.h"
#include "component.h"
#include "purl_scan.h"

/* Single purl entry: the purl, the set of versions seen and the best rank */
typedef struct purl_entry_t
{
	char *purl;
	char **versions;
	int n_versions;
	int versions_cap;
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
 * @brief Add a version to a purl entry, ignoring duplicates and empty values.
 */
static void purl_entry_add_version(purl_entry_t *e, const char *version)
{
	if (!version || !*version)
		return;

	for (int i = 0; i < e->n_versions; i++)
		if (!strcmp(e->versions[i], version))
			return;

	if (e->n_versions >= e->versions_cap)
	{
		e->versions_cap = e->versions_cap ? e->versions_cap * 2 : 8;
		e->versions = realloc(e->versions, e->versions_cap * sizeof(char *));
	}
	e->versions[e->n_versions++] = strdup(version);
}

/* qsort comparators for deterministic output */
static int version_cmp(const void *a, const void *b)
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
 * @brief file table recordset handler. Each record holds a 16 byte url id
 * followed by the (encrypted) path; for every url id we query the url table.
 */
static bool handle_file_for_purls(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
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
	if (!file_md5_hex || !valid_md5(file_md5_hex))
	{
		fprintf(stdout, "Invalid file MD5: %s\n", file_md5_hex ? file_md5_hex : "(null)");
		return EXIT_FAILURE;
	}

	uint8_t file_md5[MD5_LEN];
	ldb_hex_to_bin(file_md5_hex, MD5_LEN * 2, file_md5);

	purl_scan_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));

	ldb_fetch_recordset(NULL, oss_file, file_md5, false, handle_file_for_purls, &ctx);

	scanlog("purl_scan: %d unique purls found across %u files for %s\n", ctx.count, ctx.files_processed, file_md5_hex);

	/* Sort entries (rank asc, then purl) and versions for a deterministic output */
	purl_entry_t **sorted = NULL;
	if (ctx.count)
	{
		sorted = malloc(ctx.count * sizeof(purl_entry_t *));
		int i = 0;
		for (purl_entry_t *e = ctx.head; e; e = e->next)
		{
			if (e->n_versions > 1)
				qsort(e->versions, e->n_versions, sizeof(char *), version_cmp);
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
			printf("{\"purl\": \"%s\", \"versions\": [", e->purl);
			for (int v = 0; v < e->n_versions; v++)
			{
				if (v)
					printf(", ");
				printf("\"%s\"", e->versions[v]);
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
		for (int v = 0; v < e->n_versions; v++)
			free(e->versions[v]);
		free(e->versions);
		free(e->purl);
		free(e);
		e = next;
	}

	return EXIT_SUCCESS;
}
