// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/keywords.c
 *
 * Routines for analyzing keywords found in URL and file path
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

#include "keywords.h"
#include "blacklist.h"
#include "limits.h"
#include "debug.h"
#include "parse.h"

/* Add a keyword to the keyword list structure array */
void add_keyword(struct keywords *kwlist, char *word, int word_len)
{

	const int max_word = 1024;
	char tmpword[max_word];
	strncpy(tmpword, word, word_len);
	tmpword[word_len]=0;
	lowercase(tmpword);	

	/* Avoid unwanted words */
	int i = 0;
	while (IGNORE_KEYWORDS[i])
		if (!strcmp(tmpword, IGNORE_KEYWORDS[i++]))
			return;

	bool found = false;
	i = 0;
	for (; i < MATCH_ANALYZE_KEYWORD_LIMIT && *kwlist[i].word; i++)
	{
		if (!strcmp(kwlist[i].word, tmpword))
		{
			kwlist[i].count++;
			found = true;
			break;
		}
	}
	
	if (!found) if (i < MATCH_ANALYZE_KEYWORD_LIMIT)
	{
		strcpy(kwlist[i].word, tmpword);
		kwlist[i].count = 1;
	}
}

/* Dump keyword list to STDOUT */
void list_keywords(struct keywords *kwlist)
{
	for (int i = 0; i < MATCH_ANALYZE_KEYWORD_LIMIT && *kwlist[i].word; i++)
		printf("%s (%d)\n", kwlist[i].word, kwlist[i].count);
}

/* Return the index of the mostly repeated keyword */
int best_keyword(struct keywords *kwlist)
{
	int best = 0;
	int out = 0;
	for (int i = 0; i < MATCH_ANALYZE_KEYWORD_LIMIT && *kwlist[i].word; i++)
	{
		if (kwlist[i].count > best)
		{ 
			best = kwlist[i].count;
			out = i;
		}
	}
	return out;
}

/* Checks if the word is found in the path */
bool found_keyword(char *word, char *path)
{

	char *ptr = path;
	char *start = path;
	int length = strlen(word);
	
	/* Search for the last slash to delimit the basepath */
	int len = strlen(path);
	for (; len > 0; len--) if (path[len - 1] == '/') break;

	while (*ptr && ptr < (path + len))
	{
		if (!isalnum(*ptr))
		{
			int word_len = ptr - start;
			if (word_len == length) if (!memcmp(word, start, word_len)) return true; 
			start = ptr + 1;
		}
		ptr++;
	}

	return false;
}

/* Breaks a basepath into keywords and adds them to the list */
void add_keywords(struct keywords *kwlist, char *path)
{
	const int min_word = 4;
	const int max_word = 1024;
	char *ptr = path;
	char *start = path;
	
	/* Search for the last slash to delimit the basepath */
	int len = strlen(path);
	for (; len > 0; len--) if (path[len - 1] == '/') break;

	while (*ptr && ptr < (path + len))
	{
		if (!isalnum(*ptr))
		{
			int word_len = ptr - start;
			if (word_len < max_word && word_len >= min_word) add_keyword(kwlist, start, word_len);
			start = ptr + 1;
		}
		ptr++;
	}
}

/* Recurse matches and analyze paths, selecting the most relevant keyword */
struct keywords *load_keywords(match_data *matches)
{
	struct keywords *kwlist = calloc(sizeof(keywords), MATCH_ANALYZE_KEYWORD_LIMIT);

	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		add_keywords(kwlist, matches[i].file);
		add_keywords(kwlist, skip_domain(matches[i].url));
	}
	return kwlist;
}

/* Returns true if both version and latest_version are present and are smaller
   than 16 bytes (rules out commit IDs and hashes in version) */
bool good_version_range(match_data match)
{
	if (*match.version)
	if (*match.latest_version)
	if (strlen(match.version) < 2 * MD5_LEN)
	if (strlen(match.latest_version) < 2 * MD5_LEN) return true;
	return false;
}

bool wordicmp(char *word1, char *word2)
{
	char *w1 = word1;
	char *w2 = word2;
	while (*w1 && *w2)
	{
		if (tolower(*(w1++)) != tolower(*(w2++))) return false;
	}
	return true;
}

bool stristr(char *haystack, char *needle)
{
	char *h = haystack;
	while (*h) if (wordicmp(h++, needle)) return true;
	return false;
}

int select_exact_component_by_keyword(match_data *matches, char *component)
{
	/* Search for keyword match in vendor and component with version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		if (good_version_range(matches[i]))
			if (stristr(matches[i].component, component))
			if (stristr(matches[i].vendor, component))
			{
				matches[i].selected = true;
				scanlog("Selected keyword match in vendor and component with version range\n");
				return i;
			}
	}

	/* Search for matches in component with version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		if (good_version_range(matches[i]))
			if (stristr(matches[i].component, component))
			{
				matches[i].selected = true;
				scanlog("Selected match in component with version range\n");
				return i;
			}
	}

	/* Search for matches in component without version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		if (!strcmp(matches[i].component, component))
		{
			matches[i].selected = true;
			scanlog("Selected match in component without version range\n");
			return i;
		}
	}
	
	return -1;
}

int select_by_keyword_in_path(match_data *matches, char *keyword)
{

	/* Search for matches in URL with version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		if (good_version_range(matches[i])) 
		if (found_keyword(keyword, matches[i].url)) return true;
		{
			matches[i].selected = true;
			return i;
		}
	}

	/* Search for matches in file path with version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		if (good_version_range(matches[i])) 
		if (found_keyword(keyword, matches[i].file)) return true;
		{
			matches[i].selected = true;
			return i;
		}
	}

	/* Search for matches in URL without version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		if (found_keyword(keyword, matches[i].url)) return true;
		{
			matches[i].selected = true;
			return i;
		}
	}

	/* Search for matches in file path without version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		if (found_keyword(keyword, matches[i].file)) return true;
		{
			matches[i].selected = true;
			return i;
		}
	}
	return -1;
}

bool select_match(match_data *matches, struct keywords *kwlist)
{
	int best = best_keyword(kwlist);
	int selected = -1;

	if (kwlist[best].count < 2) return false;
	scanlog("Best component: %s (%d)\n", kwlist[best].word, kwlist[best].count);

	selected = select_exact_component_by_keyword(matches, kwlist[best].word);

	if (selected < 0) selected = select_by_keyword_in_path(matches, kwlist[best].word);
	if (selected) scanlog("Selected by keyword in path\n");

	if (selected >= 0)
	{
		if (debug_on)
		{
			/* Search for matches with version ranges first */
			for (int i = 0; i < scan_limit && *matches[i].component; i++)
			{
				scanlog("Matched: %d %s/%s version %s %s\n", i, matches[i].vendor,matches[i].component, matches[i].version, i==selected?"[SELECTED]":"");
				scanlog("          %s\n", matches[i].url);
			}
		}
		if (!*matches[selected].vendor) strcpy(matches[selected].vendor, kwlist[best].word);
		if (!*matches[selected].version) strcpy(matches[selected].version, "?");
		if (!*matches[selected].latest_version) strcpy(matches[selected].latest_version, "?");
		matches[selected].selected = true;
	}

	return true;
}

/* Perform keyword analysis among URL and file paths, find a common denominator and
   pick a URL/file containing such keyboard as the only match */
void keyword_analysis(match_data *matches)
{
	/* A single match does not need to be analyzed */	
	if (count_matches(matches) <= 1) return;

	scanlog("Loading keywords\n");
	struct keywords *kwlist = load_keywords(matches);

	scanlog("Selecting match\n");
	select_match(matches, kwlist);

	free(kwlist);
}
