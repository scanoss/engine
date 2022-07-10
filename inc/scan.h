#ifndef __SCAN_H
    #define __SCAN_H

#include "scanoss.h"

int get_component_age(uint8_t *md5);
int hash_scan(char *path, int scan_max_snippets, int scan_max_components);
bool asset_declared(component_data_t * comp);
#endif
