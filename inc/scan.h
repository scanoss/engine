#ifndef __SCAN_H
    #define __SCAN_H

#include "scanoss.h"

scan_data scan_data_init();
char *parse_sbom(char *filepath);

#endif