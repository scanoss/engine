#ifndef __SCAN_H
    #define __SCAN_H

#include "scanoss.h"

int get_component_age(uint8_t *md5);
int hash_scan(scan_data_t *scan);
bool asset_declared(component_data_t * comp);
#endif
