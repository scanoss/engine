#ifndef __VERSIONS_H
    #define __VERSIONS_H

#include "scanoss.h"

void normalise_version(char *version, char *component);
void clean_versions(match_data *match);
void add_versions(match_data *matches, file_recordset *files, uint32_t records);

char * version_cleanup(char *  version, char * component);
#endif
