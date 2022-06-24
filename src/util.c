// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/util.c
 *
 * Data conversion and handling utilities
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
  @file util.c
  @date 12 Jul 2020
  @brief Contains mixed funtions with general utilities
 
  Long description // TODO
  @see https://github.com/scanoss/engine/blob/master/src/util.c
 */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "util.h"
#include "limits.h"
#include "debug.h"
#include "license.h"
#include "ldb.h"
#include "crc32c.h"

/**
 * @brief Returns a pointer to field n in data
 * @param n field number
 * @param data data buffer
 * @return pointer to field
 */
char *field_n(int n, char *data)
{
  int commas = 0;
  while (*data) if (*data++ == ',') if (++commas == n-1) return data;
  return NULL;
}

/**
 * @brief Case insensitive string start comparison,
	returns true if a starts with b or viceversa
 * @param a string a
 * @param b string b
 * @return true if start the same
 */
bool stristart(char *a, char *b)
{
	if (!*a || !*b) return false;
	while (*a && *b) if (tolower(*a++) != tolower(*b++)) return false;
	return true;
}

/**
 * @brief Reverse an uint32 number
 * @param data pointer to daa buffer to be inverted
 */
void uint32_reverse(uint8_t *data)
{
	uint8_t tmp = data[0];
	data[0] = data[3];
	data[3] = tmp;
	tmp = data[1];
	data[1] = data[2];
	data[2] = tmp;
}

/**
 * @brief Compares two MD5 checksums
 * @param md51 md5 1
 * @param md52 md5 2
 * @return true for equal
 */
bool md5cmp(uint8_t *md51, uint8_t *md52)
{
	for (int i = 0; i < 16; i++)
		if (md51[i] != md52[i])
			return false;
	return true;
}

/**
 * @brief Trim str
 * @param str string to trim
 */
void trim(char *str)
{
    int i = 0;

    /* Left trim */
    int len = strlen(str);
    for (i = 0; i < len; i++) if (!isspace(str[i])) break;
    if (i) memmove(str, str + i, strlen(str + i) + 1);

    /* Right trim */
    len = strlen(str);
    for (i = len - 1; i >= 0 ; i--) if (!isspace(str[i])) break;
    str[i + 1] = 0;
}

/**
 * @brief Returns the pair md5 of "component/vendor"
 * @param component component string
 * @param vendor vendor sting
 * @param out[out] pointer ot md5
 */
void vendor_component_md5(char *component, char *vendor, uint8_t *out)
{
	char pair[1024] = "\0";
	if (strlen(component) + strlen(vendor) + 2 >= 1024) return;

	/* Calculate pair_md5 */
	sprintf(pair, "%s/%s", component, vendor);
	for (int i = 0; i < strlen(pair); i++) pair[i] = tolower(pair[i]);
	MD5((uint8_t *)pair, strlen(pair), out);

	/* Log pair_md5 */
	char hex[MD5_LEN * 2 + 1] = "\0";
	ldb_bin_to_hex(out, MD5_LEN, hex);
	scanlog("vendor/component: %s = %s\n", pair, hex);
}

/**
 * @brief  Removes chr from str
 * @param str input string
 * @param chr char to be removed
 */
void remove_char(char *str, char chr)
{
	char *s = str;
	while (*s)
	{
		if (*s == chr) memmove(s, s + 1, strlen(s + 1) + 1);
		else s++;
	}
}

/**
 * @brief Cleans str from unprintable characters or quotes
 * @param str string to be processed
 */
void string_clean(char *str)
{
  char *s = str;
  while (*s)
  {
    if (*s < ' ' || *s == '"') *s = ' ';
    else s++;
  }
}

char * json_remove_invalid_char(char * input)
{
	const char unwanted[] = "\\";

	for (int i = 0; i < strlen(unwanted); i++)
	{
		char * ch = strchr(input, unwanted[i]);
		while (ch != NULL)
		{
			*ch = ' ';
			ch = strchr(input, unwanted[i]);
		}
	}

	return input;
}


/**
 * @brief Returns the current date stamp
 * @return pointer to date string
 */
char *datestamp()
{
	time_t timestamp;
	struct tm *times;
	time(&timestamp);
	times = localtime(&timestamp);
	char *stamp = malloc(MAX_ARGLN);
	strftime(stamp, MAX_ARGLN, "%FT%T%z", times);
	return stamp;
}

/**
 * @brief Prints a "created" JSON element with the current datestamp
 */
void print_datestamp()
{
	char *stamp = datestamp();
	printf("%s", stamp);
	free(stamp);
}

/**
 * @brief Returns a string with a hex representation of md5
 * @param md5 input md5
 * @return pointer to string
 */
char *md5_hex(uint8_t *md5)
{
	char *out =  calloc(2 * MD5_LEN + 1, 1);
	for (int i = 0; i < MD5_LEN; i++) sprintf(out + strlen(out), "%02x", md5[i]);
	return out;
}

/**
 * @brief Returns the CRC32C for a string
 * @param str input string
 * @return crc32
 */
uint32_t string_crc32c(char *str)
{
	return calc_crc32c (str, strlen(str));
}

/**
 * @brief Check if a crc is found in the list (add it if not)
 * @param list pointer to list
 * @param crc input crc
 * @return true if the crc was found in the list
 */
bool add_CRC(uint32_t *list, uint32_t crc)
{
	if (!list)
		return false;
		
	for (int i = 0; i < CRC_LIST_LEN; i++)
	{
		if (list[i] == 0)
		{
			list [i] = crc;
			return false;
		}
		if (list[i] == crc) return true;
	}
	return false;
}

/* Case insensitive string comparison */
bool strn_icmp(char *a, char *b, int len)
{
    for (int i = 0; i < len; i++) if (tolower(a[i]) != tolower(b[i])) return false;
    return true;
}

/* Check if a string starts with the given start string */
bool starts_with(char *str, char *start)
{
    if (!str)
		return false;
		
	int len = strlen(start);
    if (strn_icmp(str, start, len)) return true;
    return false;
}

/* Returns true if str is a valid MD5 hash */
bool valid_md5(char *str)
{
	if (strlen(str) != 32) return false;

	char *p = str;
	while (*p)
	{
		if (!isdigit(*p) && (*p < 'a' || *p >'f')) return false;
		p++;
	}

	return true;
}

char * str_cat_realloc(char **a, char * b)
{
	char * aux = *a;
	if (!aux)
	{
		asprintf(a,"%s", b);	
	}
	else
	{
		*a = NULL;
		asprintf(a,"%s%s", aux, b);
		free(aux);
	}
	
	return *a;
}

