#ifndef __SCAN_H
    #define __SCAN_H

#include "scanoss.h"

scan_data scan_data_init();
char *parse_sbom(char *filepath);
uint8_t *biggest_snippet(scan_data *scan);

#endif
