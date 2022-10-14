#ifndef __COMPONENT_H
#define __COMPONENT_H

#include "scanoss.h"
/**
 * @brief Component object definition.
 * 
 */
enum {
	IDENTIFIED_NONE = 0,
	IDENTIFIED_PURL,
	IDENTIFIED_PURL_VERSION
};

typedef struct component_data_t
{
	char * vendor; /* component vendor */
	char * component; /* component name */
	char * version; /* component version */
	char * release_date; /* component release date */
	char * latest_release_date; /* lastest relese date for this component */
	char * latest_version; /* lastest version for this component */
	char * license; /* component declared license */
	char * url; /* component url */
	char * file; /* component file path */	
	char * main_url; /* main file url in the component */
	bool url_match; /* type of url match*/
	/* PURL array */
	char *purls[MAX_PURLS]; /* PURLs array */
	uint8_t *purls_md5[MAX_PURLS]; /*PURLs md5*/
	int vulnerabilities; /*component vulnerabilities number */
	int identified; /* was this component indentified in a provided SBOM: 0 = pending, 1 = identified without version, 2= identified with version */
	int path_ln; /* component path lenght: number of subdirectories in the path*/
	uint8_t url_md5[MD5_LEN]; /*url md5*/
	int age; /*component age */
	uint32_t * crclist; /* pointer to crc list used in part of the process */
	uint8_t * file_md5_ref; /*pointer to the md5 of the matched file */
	char * copyright_text; /* used in json output generation */
	char *license_text; /* used in json output generation */
	char * vulnerabilities_text; /* used in json output generation */
	char * dependency_text; /* used in json output generation */
} component_data_t;

component_data_t * component_init(void);
void component_data_free(component_data_t * data);
bool fill_component(component_data_t * component, uint8_t *url_key, char *file_path, uint8_t *url_record);
bool component_date_comparation(component_data_t * a, component_data_t * b);
component_data_t * component_data_copy(component_data_t * in);
int asset_declared(component_data_t * comp);
void component_item_free(component_item * comp_item);

#endif