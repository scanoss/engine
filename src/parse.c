// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/parse.c
 *
 * Data parsing subroutines
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

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "limits.h"
#include "parse.h"
#include "json.h"
#include "debug.h"

static bool is_component(char *str)
{
	if (!strcmp(str, "name")) return true;
	if (!strcmp(str, "component")) return true;
	return false;
}

static bool is_vendor(char *str)
{
	if (!strcmp(str, "publisher")) return true;
	if (!strcmp(str, "vendor")) return true;
	return false;
}

static void json_process_value(json_value* value, int depth, char *out, bool load_vendor, bool load_component, bool load_purl);

static void json_process_object(json_value* value, int depth, char *out, bool load_vendor, bool load_component, bool load_purl)
{
	int length, x;
	if (value == NULL) return;

	char vendor[MAX_ARGLN] = "\0";
	char component[MAX_ARGLN] = "\0";
	char purl[MAX_PATH] = "\0";

	length = value->u.object.length;
	for (x = 0; x < length; x++)
	{
		json_value *data = value->u.object.values[x].value;
		char *name = value->u.object.values[x].name;

		if (!strcmp(value->u.object.values[x].name, "Document") ||
				(!strcmp(value->u.object.values[x].name, "components")) ||
				(!strcmp(value->u.object.values[x].name, "purl")) ||
				(!strcmp(value->u.object.values[x].name, "packages")))
		{
			json_process_value(value->u.object.values[x].value, depth+1, out, load_vendor, load_component, load_purl);
		}
		if (data->type == json_string)
		{
			/* Copy vendor name */
			if (is_vendor(name) && load_vendor)
			{
				strcpy(vendor, data->u.string.ptr);
			}

			/* Copy component name */
			if (is_component(name) && load_component)
			{
				strcpy(component, data->u.string.ptr);
			}

			if (!strcmp(name, "purl") && load_purl)
			{
				strcpy(purl, data->u.string.ptr);
			}
		}
	}

	if (!*component && !*vendor && !*purl) return;

	if (*purl)
	{
		sprintf(out + strlen(out), "%s,", purl);
	}

	if (!load_vendor)
	{
		sprintf(out + strlen(out), "%s,", component);
		return;
	}

	if (*component && *vendor)
	{
		sprintf(out + strlen(out), "%s/%s,", vendor, component);
	}
}

static void json_process_array(json_value* value, int depth, char *out, bool load_vendor, bool load_component, bool load_purl)
{
	int length, x;
	if (value == NULL) return;

	length = value->u.array.length;
	for (x = 0; x < length; x++) {
		json_process_value(value->u.array.values[x], depth, out, load_vendor, load_component, load_purl);
	}
}

static void json_process_value(json_value* value, int depth, char *out, bool load_vendor, bool load_component, bool load_purl)
{
	if (value == NULL) return;

	switch (value->type)
	{
		case json_object:
			json_process_object(value, depth+1, out, load_vendor, load_component, load_purl);
			break;

		case json_array:
			json_process_array(value, depth+1, out, load_vendor, load_component, load_purl);
			break;

		default:
			break;
	}
}

/* Loads assets (SBOM.json) into memory */
char *parse_sbom(char *filepath, bool load_vendor, bool load_component, bool load_purl)
{
	json_char* json;
	json_value* value;

	/* Read file into buffer */
	FILE *file;
	if((file = fopen(filepath, "rb"))==NULL)
	{ 
		printf("Error: %s cannot be loaded\n",filepath);
		exit(EXIT_FAILURE);
	}
	
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
	json_process_value(value, 0, out, load_vendor, load_component, load_purl);

	json_value_free(value);
	free(buffer);

	/* Convert to lowercase */
	for (int i = 0; i < strlen(out); i++) out[i] = tolower(out[i]);

	/* Trim trailing comma */
	if (out[strlen(out) - 1] == ',') out[strlen(out) - 1] = 0;

	scanlog("SBOM contents: %s\n", out);

	return out;
}

/* Returns a pointer to the character following the first "character" in "data" */
char *skip_first_char(char *data, char character)
{
	char *ptr = data;
	while (*ptr)
	{
		if (*ptr == character) return ++ptr;
		ptr++;
	}
	return data;
}

/* Returns a pointer to the character following the first comma in data */
char *skip_first_comma(char *data)
{
	return skip_first_char(data, ',');
}

/* Returns a pointer to the character following the first slash in data */
char *skip_first_slash(char *data)
{
	return skip_first_char(data, '/');
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

