#ifndef __COMPONENT_H
#define __COMPONENT_H

#include "scanoss.h"
#include "limits.h"

#define COMPONENT_DEFAULT_RANK 999 //default rank for components without rank information
#define COMPONENT_RANK_SELECTION_MAX 8 //max rank to be considered in component selection

extern int component_rank_max;

// Third-party confidence thresholds for path_is_third_party()
#define TP_THRESHOLD_HIGH 12    // 0-11: high confidence third-party (node_modules, vendor, etc.)
#define TP_THRESHOLD_MED  27    // 12-26: medium confidence (external, dependencies, etc.)
                                // 27-31: medium-low confidence (dist, contrib, etc.)
                                // 32+: not third-party
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
	int dependencies;
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
	char * health_text; /* used in json output generation */
	int hits; /*used in binary analysis*/
	char * file_path_ref;
	int path_rank; /* Path ranking index*/
	int url_stats[5]; /* url stats: quantity of file */
	int health_stats[3]; /* health stats: forks, watchers, contributors */
	int rank; /* purl ranking - optional*/
	int path_depth; /* depth of the matched file path*/
	int third_party_rank; /* Saves third party ranking*/
} component_data_t;

typedef struct keywords
{
	int  count;
	char word[MAX_FIELD_LN];
} keywords;


typedef struct file_recordset
{
	uint8_t url_id[MD5_LEN];
	char path[MAX_FILE_PATH];
	int path_ln;
	bool external;
} file_recordset;

typedef struct len_rank
{
	int id;
	int len;
} len_rank;

typedef struct  component_item
{
	char * vendor;
	char * component;
	char * purl;
	char * version;
	char * license;
} component_item;

extern component_item *ignore_components;
extern component_item *declared_components;


component_data_t * component_init(void);
void component_data_free(component_data_t * data);
bool fill_component(component_data_t * component, uint8_t *url_key, char *file_path, uint8_t *url_record);
bool component_date_comparation(component_data_t * a, component_data_t * b);
component_data_t * component_data_copy(component_data_t * in);
int asset_declared(component_data_t * comp);
void component_item_free(component_item * comp_item);
void fill_component_path(component_data_t *component, char *file_path);
#endif