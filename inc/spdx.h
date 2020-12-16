#ifndef __SPDX_H
    #define __SPDX_H

#include "scanoss.h"

void spdx_open(void);
void spdx_xml_open(scan_data *scan);
void spdx_close(void);
void spdx_xml_close(void);
void print_json_match_spdx(scan_data scan, match_data match);
void print_xml_match_spdx(scan_data scan, match_data match);





    

#endif