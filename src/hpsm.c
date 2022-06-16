// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/hpsm.c
 *
 * High Precision Snippet Matching subroutines
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

#include "hpsm.h"
#include <string.h>
#include <dlfcn.h>

#include "debug.h"
#include "util.h"

bool hpsm_lib_present = false;;
bool hpsm_enabled = false;
struct ranges hpsm_result;
/* HPSM - Normalized CRC8 for each line */
char *hpsm_crc_lines = NULL;

/* HPSM function pointers */
char *(*hpsm_hash_file_contents)(char *data);
struct ranges (*hpsm)(char *data, char *md5);
struct ranges (*hpsm_process)(unsigned char *data, int length, char *md5);

void * lib_hpsm_handle = NULL;
bool hpsm_lib_load()
{
		/*set decode funtion pointer to NULL*/
	lib_hpsm_handle = dlopen("libhpsm.so", RTLD_NOW);
	char * err;
    if (lib_hpsm_handle) 
	{
		scanlog("Lib HPSM present\n");
		hpsm_hash_file_contents = dlsym(lib_hpsm_handle, "HashFileContents");
		hpsm = dlsym(lib_hpsm_handle, "HPSM");
		hpsm_process = dlsym(lib_hpsm_handle, "ProcessHPSM");
		if ((err = dlerror())) 
		{
			printf("%s\n", err);
			exit(EXIT_FAILURE);
		}
        hpsm_lib_present = true;
		return true;
    }
	hpsm_hash_file_contents = NULL;
	hpsm = NULL;
	hpsm_process = NULL;
    hpsm_lib_present = false;
	return false;
}

void hpsm_lib_close()
{
    if (hpsm_lib_present)
	{
		dlclose(lib_hpsm_handle);
		free(hpsm_crc_lines);
        free(hpsm_result.local);
        free(hpsm_result.matched);
        free(hpsm_result.remote);
	}
}

bool hpsm_calc(uint8_t *file_md5)
{
    
    if (!hpsm_enabled)
        return true;

    if (!hpsm_lib_present)
    {
        hpsm_enabled = false;
        scanlog("Warning, hpsm header detected in WFP but 'libhpsm.so' is not available, skiping HPSM analisys\n");
        return true;
    }
    
    if (!hpsm_crc_lines)
    {
        scanlog("Warning, No lines CRC to process, skiping HPSM analisys\n");
        return false;
    }
    scanlog("Running HPSM\n");
    char *file = md5_hex(file_md5);
    hpsm_result = hpsm(hpsm_crc_lines, file);
    free(file);

    if (memcmp(hpsm_result.matched, "0%%", 2))
        return true;

    return false;
}

struct ranges * hpsm_get_result()
{
    return &hpsm_result;
}
