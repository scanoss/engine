// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/keywords.c
 *
 * Routines for analyzing keywords found in URL and file path
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
  * @file keywords.c
  * @date 1 Jun 2021 
  * @brief //TODO
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/keywords.c
  */

#include "keywords.h"
#include "ignorelist.h"
#include "limits.h"
#include "debug.h"
#include "parse.h"

/**
 * @brief Add a keyword to the keyword list structure array
 * @param kwlist pointer to keyword list structure
 * @param word keyword to add
 * @param word_len keyword len
 */
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

/**
 * @brief Dump keyword list to STDOUT
 * @param kwlist pointer to key word list
 */
void list_keywords(struct keywords *kwlist)
{
	for (int i = 0; i < MATCH_ANALYZE_KEYWORD_LIMIT && *kwlist[i].word; i++)
		printf("%s (%d)\n", kwlist[i].word, kwlist[i].count);
}

/**
 * @brief Return the index of the mostly repeated keyword
 * @param kwlist pointer to keyword list
 * @return index of the selected word
 */
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

/**
 * @brief Checks if the word is found in the path
 * @param word word to search
 * @param path path where do the search
 * @return true is the word has been found
 */
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

/**
 * @brief Breaks a basepath into keywords and adds them to the list 
 * @param kwlist pointer to keywords structure
 * @param path patht o analyze
 */
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

/**
 * @brief Recurse matches and analyze paths, selecting the most relevant keyword
 * @param matches list of matches to analyze
 * @return keywords list.
 */
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

/**
 * @brief Returns true if both version and latest_version are present and are smaller
 * than 16 bytes (rules out commit IDs and hashes in version)
 * @param match match to analyze
 * @return true if lastest_version is similar to version
 */
bool good_version_range(match_data match)
{
	/* Both versions must be present */
	if (!*match.version || !*match.latest_version) return false;

	/* Ignore commit hashes in version */
	if (strlen(match.version) >= (2 * MD5_LEN)) return false;
	if (strlen(match.latest_version) >= (2 * MD5_LEN)) return false;

	/* Return true if there is a verson range */
	if (strcmp(match.version, match.latest_version)) return true;

	return false;
}

/**
 * @brief word case insensitive comparation
 * @param word1 first word
 * @param word2 second word
 * @return true if they are equals
 */
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

/**
 * @brief str insensitive str
 * @param haystack haystack
 * @param needle needle
 * @return true is the needle is found into the haystack
 */
bool stristr(char *haystack, char *needle)
{
	char *h = haystack;
	while (*h) if (wordicmp(h++, needle)) return true;
	return false;
}

/**
 * @brief Search for a component inside a mathes list
 * @param matches matches list
 * @param component component to search for
 * @return index if it was found or -1 if is not present.
 */
int select_exact_component_by_keyword(match_data *matches, char *component)
{
	/* Search for matches in component with version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		if (stricmp(matches[i].component, component))
			if (good_version_range(matches[i]))
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

/**
 * @brief Search for a keyword inside a matches list
 * @param matches matches list where do the search
 * @param keyword keyword 
 * @return index if it was found or -1 if is not present.
 */
int select_by_keyword_in_path(match_data *matches, char *keyword)
{

	/* Search for matches in URL with version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		if (found_keyword(keyword, matches[i].url))
			if (good_version_range(matches[i]))
			{
				matches[i].selected = true;
				return i;
			}
	}

	/* Search for matches in file path with version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		if (found_keyword(keyword, matches[i].file))
			if (good_version_range(matches[i]))
			{
				matches[i].selected = true;
				return i;
			}
	}

	/* Search for matches in URL without version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		if (found_keyword(keyword, matches[i].url))
		{
			matches[i].selected = true;
			return i;
		}
	}

	/* Search for matches in file path without version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		if (found_keyword(keyword, matches[i].file))
		{
			matches[i].selected = true;
			return i;
		}
	}
	return -1;
}

/**
 * @brief select the best match from a matches list
 * @param matches matches list
 * @param kwlist keywords list
 * @return true if there is a match
 */
bool select_match(match_data *matches, struct keywords *kwlist)
{
	scanlog("Running select_match starts()\n");
	if (!*component_hint)
	{
		scanlog("Skipping select_match (no component_hint identified)\n");
		return false;
	}

	int	best = best_keyword(kwlist);
	int selected = -1;

	char *best_component = component_hint;
	if (!*best_component)
	{
			best_component = kwlist[best].word;
			scanlog("Best component: %s\n", best_component);
	}

	/* Attempt selection by exact component match */
	selected = select_exact_component_by_keyword(matches, best_component);
	if (selected >= 0)
	{
		scanlog("Selected by exact component name\n");
	}

	/* Attempt selection by presence of component in path */
	else
	{
		selected = select_by_keyword_in_path(matches, best_component);
	}

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
		if (!*matches[selected].vendor) strcpy(matches[selected].vendor, best_component);
		if (!*matches[selected].version) strcpy(matches[selected].version, "?");
		if (!*matches[selected].latest_version) strcpy(matches[selected].latest_version, "?");
		matches[selected].selected = true;
	}

	return (selected >= 0);
}

/**
 * @brief Perform keyword analysis among URL and file paths, find a common denominator and
	 pick a URL/file containing such keyboard as the only match
 * @param matches matches list
 * @return true if a match was selected
 */
bool keyword_analysis(match_data *matches)
{
	/* A single match does not need to be analyzed */	
	if (count_matches(matches) <= 1)
	{
		matches[0].selected = true;
		return true;
	}

	scanlog("Loading keywords\n");
	struct keywords *kwlist = load_keywords(matches);

	scanlog("Selecting match from keywords\n");
	bool selected = select_match(matches, kwlist);

	free(kwlist);

	return selected;
}
