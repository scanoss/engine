#ifndef __REPORT_H
    #define __REPORT_H

#include "scanoss.h"

void json_open_file(char *filename);    
void json_close_file(void);
void report_close(void);
void report_open(scan_data *scan);
void print_match(scan_data scan, match_data match);
void print_json_nomatch(scan_data scan);    

#endif