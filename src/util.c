// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/util.c
 *
 * Data conversion and handling utilities
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
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "util.h"

#include "limits.h"
#include "debug.h"

/* Case insensitive string start comparison,
	returns true if a starts with b or viceversa */
bool stristart(char *a, char *b)
{
	if (!*a || !*b) return false;
	while (*a && *b) if (tolower(*a++) != tolower(*b++)) return false;
	return true;
}

/* Reverse an uint32 number  */
void uint32_reverse(uint8_t *data)
{
	uint8_t tmp = data[0];
	data[0] = data[3];
	data[3] = tmp;
	tmp = data[1];
	data[1] = data[2];
	data[2] = tmp;
}

/* Returns the numeric value of hex h */
static uint8_t h2d(uint8_t h)
{
	if (h >= '0' && h <= '9')
		return h - '0';
	else if (h >= 'a' && h <= 'f')
		return h - 'a' + 10;
	else if (h >= 'A' && h <= 'F')
		return h - 'A' + 10;
	return 0;
}

/* Converts hex to binary */
void hex_to_bin(char *hex, uint32_t len, uint8_t *out)
{
	uint32_t ptr = 0;
	for (uint32_t i = 0; i < len; i += 2)
		out[ptr++] = 16 * h2d(hex[i]) + h2d(hex[i + 1]);
}

/* Converts bin to hex */
void bin_to_hex(uint8_t *bin, uint32_t len, char *out)
{
	*out = 0;
	for (uint32_t i = 0; i < len; i++)
		sprintf(out + strlen(out), "%02x", bin[i]);
}

/* Compares two MD5 checksums */
bool md5cmp(uint8_t *md51, uint8_t *md52)
{
	for (int i = 0; i < 16; i++)
		if (md51[i] != md52[i])
			return false;
	return true;
}

/* Trim str */
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

/* Trim string at first non-printable char */
void printable_only(char *text)
{
	for (int i = 0; i < strlen(text); i++)
		if (text[i] < '"' || text[i] > 'z') text[i] = 0;
}

/* Returns the pair md5 of "component/vendor" */
void component_vendor_md5(char *component, char *vendor, uint8_t *out)
{
	char pair[1024] = "\0";
	if (strlen(component) + strlen(vendor) + 2 >= 1024) return;

	/* Calculate pair_md5 */
	sprintf(pair, "%s/%s", component, vendor);
	for (int i = 0; i < strlen(pair); i++) pair[i] = tolower(pair[i]);
	MD5((uint8_t *)pair, strlen(pair), out);

	/* Log pair_md5 */
	char hex[MD5_LEN * 2 + 1] = "\0";
	bin_to_hex(out, MD5_LEN, hex);
	scanlog("vendor/component: %s = %s\n", pair, hex);
}

/* Removes chr from str */
void remove_char(char *str, char chr)
{
	char *s = str;
	while (*s)
	{
		if (*s == chr) memmove(s, s + 1, strlen(s + 1) + 1);
		else s++;
	}
}


/* Returns the current date stamp */
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

/* Prints a "created" JSON element with the current datestamp */
void print_datestamp()
{
	char *stamp = datestamp();
	printf("%s", stamp);
	free(stamp);
}

/* Returns a string with a hex representation of md5 */
char *md5_hex(uint8_t *md5)
{
	char *out =  calloc(2 * MD5_LEN + 1, 1);
	for (int i = 0; i < MD5_LEN; i++) sprintf(out + strlen(out), "%02x", md5[i]);
	return out;
}

