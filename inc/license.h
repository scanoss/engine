#ifndef __LICENSE_H
    #define __LICENSE_H

#include "scanoss.h"
#include "match_list.h"

void print_licenses(component_data_t * comp);
void print_osadl_license_data(char *license);
bool osadl_load_file(void);
#endif
