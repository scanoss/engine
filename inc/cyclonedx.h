#ifndef __CYCLONEDEX_H
    #define __CYCLONEDEX_H

#include "scanoss.h"

void cyclonedx_open(void);
void cyclonedx_close(void);
void print_json_match_cyclonedx(scan_data scan, match_data match);


#endif