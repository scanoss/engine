// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/parse.c
 *
 * Data parsing subroutines
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
#include <ctype.h>

#include "parse.h"
#include "json.h"
#include "debug.h"

static void json_process_value(json_value* value, int depth, char *out);

static void json_process_object(json_value* value, int depth, char *out)
{
        int length, x;
        if (value == NULL) return;
        
        length = value->u.object.length;
        for (x = 0; x < length; x++) {
			if ((!strcmp(value->u.object.values[x].name,"name")) ||
					(!strcmp(value->u.object.values[x].name,"components")) ||
					(!strcmp(value->u.object.values[x].name,"Document")) ||
					(!strcmp(value->u.object.values[x].name,"packages")))
				json_process_value(value->u.object.values[x].value, depth+1, out);
		}
}

static void json_process_array(json_value* value, int depth, char *out)
{
	int length, x;
	if (value == NULL) return;
	
	length = value->u.array.length;
	for (x = 0; x < length; x++) {
		json_process_value(value->u.array.values[x], depth, out);
	}
}

static void json_process_value(json_value* value, int depth, char *out)
{
	if (value == NULL) return;

	switch (value->type) {
		case json_object:
			json_process_object(value, depth+1, out);
			break;
		case json_array:
			json_process_array(value, depth+1, out);
			break;
		case json_string:
			strcat(out, value->u.string.ptr);
			strcat(out,",");
			break;
		default:
			break;
	}
}

/* Loads assets (SBOM.json) into memory */
char *parse_sbom(char *filepath)
{
	json_char* json;
	json_value* value;

	/* Read file into buffer */
	FILE *file = fopen(filepath, "rb");
	fseek(file, 0, SEEK_END);
	long file_size = ftell(file);
	fseek(file, 0, SEEK_SET);
	char *buffer = malloc(file_size + 1);
	if (!fread(buffer, 1, file_size, file)) printf("Warning: cannot parse SBOM %s\n", filepath);
	fclose(file);
	buffer[file_size] = 0;


	json = (json_char*)buffer;
	value = json_parse(json,file_size);

	if (value == NULL) {
		fprintf(stderr, "Unable to parse SBOM.json\n");
		exit(EXIT_FAILURE);
	}

	char *out = calloc(file_size + 1, 1);
	json_process_value(value, 0, out);

	json_value_free(value);
	free(buffer);
					
	scanlog("Blacklisted: %s\n", out);

	return out;
}

/* Returns a pointer to the character following the first comma in "data" */
char *skip_first_comma(char *data)
{
    char *ptr = data;
    while (*ptr)
    {
        if (*ptr == ',') return ++ptr;
        ptr++;
    }
    return data;
}

/* Extracts the "n"th value from the comma separated "in" string */
void extract_csv(char *out, char *in, int n, long limit)
{
	*out = 0;
	if (!in) return;
	if (!*in) return;

	int strln = strlen(in);
	if (strln < limit) limit = strln;

	limit--; // need an extra byte for chr(0)

	char *tmp = in;
	int n_counter = 1;
	int out_ptr = 0;

	do
	{
		if (*tmp == ',')
			n_counter++;
		else if (n_counter == n)
			out[out_ptr++] = *tmp;
	} while (*tmp++ && (n_counter <= n) && ((out_ptr + 1) < limit));

	out[out_ptr] = 0;
}

/* Returns a pointer to the path after the domain name in the provided url */
char *skip_domain(char *url)
{
	char *out = url;
	int counter = 0;
	while (*out) if (*out++ == '/') if (++counter == 3) break;

	if (counter == 3 && strlen(out) > 1) return out + 1;
	return NULL;
}

/* Converts word to lowercase */
void lowercase(char *word)
{
	for (char *w = word ; *w; w++) *w = tolower(*w);
}

