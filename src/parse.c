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

/**
  * @file parse.c
  * @date 12 Jul 2020 
  * @brief Contains the functions used for parsing and json process.
  
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/parse.c
  */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "limits.h"
#include "parse.h"
#include "json.h"
#include "debug.h"

/**
 * @brief Check if a string is a component
 * @param str input string
 * @return true if it is a component
 */
static bool is_component(char *str)
{
	if (!strcmp(str, "name")) return true;
	if (!strcmp(str, "component")) return true;
	return false;
}

/**
 * @brief Check if a string is a vendor
 * @param str input string
 * @return true if it is a vendor
 */
static bool is_vendor(char *str)
{
	if (!strcmp(str, "publisher")) return true;
	if (!strcmp(str, "vendor")) return true;
	return false;
}

/**
 * @brief Work over a json value
 * @param value pointer to json structure
 * @param depth depth into the strcuture
 * @param out[out] processed component
 */
static void work_json_value(json_value* value, int depth, component_item *out);

/**
 * @brief Work over a json object
 * @param value pointer to json structure
 * @param depth depth into the strcuture
 * @param out[out] processed component
 */
static void work_json_object(json_value* value, int depth, component_item *out)
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
			work_json_value(value->u.object.values[x].value, depth+1, out);
		}
		if (data->type == json_string)
		{
			if (is_vendor(name)) strcpy(vendor, data->u.string.ptr);
			if (is_component(name)) strcpy(component, data->u.string.ptr);
			if (!strcmp(name, "purl")) strcpy(purl, data->u.string.ptr);
		}
	}

	if (!*component && !*vendor && !*purl) return;

	/* Load values into structure */
	component_item *ignore = out;
	for (int i = 0; i < MAX_SBOM_ITEMS; i++)
	{
		if (!ignore[i].component && !ignore[i].vendor && !ignore[i].purl)
		{
			if (*vendor) 
				ignore[i].vendor = strdup(vendor);
			if (*component) 
				ignore[i].component = strdup(component);
			if (*purl) 
			{
				char * version = strrchr(purl, '@');
				if (version)
				{
					*version = '\0';
					version++;
					ignore[i].version = strdup(version);
				}
				ignore[i].purl = strdup(purl);
			}
			break;
		}
	}
}

/**
 * @brief Work over a json array
 * @param value pointer to json structure
 * @param depth depth into the strcuture
 * @param out[out] processed component
 */
static void work_json_array(json_value* value, int depth, component_item *out)
{
	int length, x;
	if (value == NULL) return;

	length = value->u.array.length;
	for (x = 0; x < length; x++) {
		work_json_value(value->u.array.values[x], depth, out);
	}
}

/**
 * @brief Work over a json value
 * @param value pointer to json structure
 * @param depth depth into the strcuture
 * @param out[out] processed component
 */
static void work_json_value(json_value* value, int depth, component_item *out)
{
	if (value == NULL) return;

	switch (value->type)
	{
		case json_object:
			work_json_object(value, depth+1, out);
			break;

		case json_array:
			work_json_array(value, depth+1, out);
			break;

		default:
			break;
	}
}

/**
 * @brief Loads assets (SBOM.json) into memory
 * @param filepath json  file path
 * @return list of component items
 */
component_item *get_components(char *filepath)
{

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
	if (!fread(buffer, 1, file_size, file)) fprintf(stderr, "Warning: cannot parse SBOM %s\n", filepath);
	fclose(file);
	buffer[file_size] = 0;

	json_char* json;
	json_value* value;

	json = (json_char*)buffer;
	value = json_parse(json,file_size);

	if (value == NULL) {
		fprintf(stderr, "Unable to parse SBOM.json\n");
		exit(EXIT_FAILURE);
	}

	component_item *out = calloc(MAX_SBOM_ITEMS * sizeof(component_item), 1);
	work_json_value(value, 0, out);

	json_value_free(value);
	free(buffer);

	scanlog("SBOM contents:\n");
	component_item *ignore = out;
	for (int i = 0; i < MAX_SBOM_ITEMS; i++)
	{
		if (!ignore[i].component && !ignore[i].vendor && !ignore[i].purl) break;
		scanlog("#%d %s, %s, %s, %s\n", i, ignore[i].component, ignore[i].vendor, ignore[i].purl, ignore[i].version);
	}

	return out;
}

/**
 * @brief Returns a pointer to the character following the first "character" in "data"
 * @param data input buffer
 * @param character key character
 * @return pointer to the next char to key in the input buffer
 */
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

/**
 * @brief Returns a pointer to the character following the first comma in data
 * @param data input data buffer
 * @return pointer to the next char to a comma in the input buffer
 */
char *skip_first_comma(char *data)
{
	return skip_first_char(data, ',');
}

/**
 * @brief Returns a pointer to the character following the first slash in data
 * @param data input data buffer
 * @return  pointer to the next char to a / in the input buffer
 */
char *skip_first_slash(char *data)
{
	return skip_first_char(data, '/');
}

/**
 * @brief Extracts the "n"th value from the comma separated "in" string
 * @param out[out] parsed string
 * @param in input buffer
 * @param n col number
 * @param limit string limit
 */
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

/**
 * @brief Returns a pointer to the path after the domain name in the provided url
 * @param url input url
 * @return pointer to the char after the domain
 */
char *skip_domain(char *url)
{
	char *out = url;
	int counter = 0;
	while (*out) if (*out++ == '/') if (++counter == 3) break;

	if (counter == 3 && strlen(out) > 1) return out + 1;
	return NULL;
}

/**
 * @brief Converts word to lowercase
 * @param word word to be converted
 */
void lowercase(char *word)
{
	for (char *w = word ; *w; w++) *w = tolower(*w);
}

