#ifndef __VERSIONS_H
    #define __VERSIONS_H

#include "scanoss.h"

typedef struct release_version
{
	char version[MAX_FIELD_LN];
	char date[MAX_FIELD_LN];
} release_version;

void normalise_version(char *version, char *component);
void add_versions(component_data_t *component, file_recordset *files, uint32_t records);
void get_purl_version(release_version *release, char *purl, uint8_t *file_id);
char * version_cleanup(char *  version, char * component);
void purl_latest_version_add(component_data_t * component);
void purl_latest_version_search(component_data_t * component);
void purl_latest_version_free();

#endif
