#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "match_list.h"
#include <ldb.h>
#include "debug.h"

int list_size = 0;
void free_and_null(void * pr)
{
    free(pr);
    pr = NULL;
}

void component_data_free(component_data_t *data)
{
    if (!data)
        return;

    free_and_null(data->vendor);
    free_and_null(data->component);
    free_and_null(data->version);
    free_and_null(data->release_date);
    free_and_null(data->latest_release_date);
    free_and_null(data->latest_version);
    free_and_null(data->license);
    free_and_null(data->url);
    free_and_null(data->file);
    free_and_null(data->main_url);
    free_and_null(data->license_text);
    free_and_null(data->dependency_text);
    free_and_null(data->vulnerabilities_text);
    free_and_null(data->copyright_text);

    for (int i = 0; i < MAX_PURLS; i++)
    {
        free_and_null(data->purls[i]);
        free_and_null(data->purls_md5[i]);
    }
    free_and_null(data);
}

component_data_t * component_data_copy(component_data_t * in)
{
    component_data_t * out = calloc(1, sizeof(*out));
    out->age = in->age;
    out->component = strdup(in->component);
    out->vendor = strdup(in->vendor);
    out->version = strdup(in->version);
    out->release_date = strdup(in->release_date);
    out->file = strdup(in->file);
    out->file_md5_ref = in->file_md5_ref;
    out->identified = in->identified;
    out->latest_release_date = strdup(in->latest_release_date);
    out->latest_version = strdup(in->latest_version);
    out->license = strdup(in->license);
    out->url_match = in->url_match;
    memcpy(out->url_md5, in->url_md5, MD5_LEN);
    if (in->main_url)
        out->main_url = strdup(in->main_url);
    out->url = strdup(in->url);
    out->path_ln = in->path_ln;
    for (int i = 0; i < MAX_PURLS; i++)
    {
        if (in->purls[i])
            out->purls[i] = strdup(in->purls[i]);
        else
            break;

        if (in->purls_md5[i])
        {
            out->purls_md5[i] = malloc(MD5_LEN);
            memcpy(out->purls_md5[i], in->purls_md5[i], MD5_LEN);
        }
    }

    return out;
}

void component_list_destroy(component_list_t *list)
{
    while (list->headp.lh_first != NULL) /* Delete. */
    {
        component_data_free(list->headp.lh_first->component);
        struct comp_entry * aux = list->headp.lh_first;
        LIST_REMOVE(list->headp.lh_first, entries);
        free(aux);
        aux = NULL;
        list->items--;
    }
}

void component_list_init(component_list_t *comp_list, int max_items)
{
    //scanlog("Init component list\n");
    LIST_INIT(&comp_list->headp); /* Initialize the list. */
    comp_list->items = 0;
    if (max_items)
        comp_list->max_items = max_items;
    else
        comp_list->autolimit = true;

    comp_list->last_element = NULL;
}

match_list_t * match_list_init(bool autolimit, int max_items, scan_data_t * scan_ref)
{
    match_list_t * list =  calloc(1, sizeof(match_list_t));
    LIST_INIT(&list->headp); /* Initialize the list. */
    list->items = 0;

    if (max_items)
		 list->max_items = max_items;
    else
		 list->max_items = 1;
   
    list->autolimit = autolimit;
    list->best_match = NULL;
    list->scan_ref = scan_ref;

    return list;
}

void match_data_free(match_data_t *data)
{
    if (!data)
        return;

    free_and_null(data->line_ranges);
    free_and_null(data->oss_ranges);
    free_and_null(data->matched_percent);
    free_and_null(data->crytography_text);
    free_and_null(data->quality_text);
    component_list_destroy(&data->component_list);
    
    free_and_null(data);
}

match_data_t * match_data_copy(match_data_t * in)
{
    match_data_t * out = calloc(1, sizeof(*out));
    memcpy(out->file_md5,in->file_md5,MD5_LEN);
    out->hits = in->hits;
    out->type = in->type;
    out->line_ranges = strdup(in->line_ranges);
    out->oss_ranges = strdup(in->oss_ranges);
    out->matched_percent = strdup(in->matched_percent);
    strcpy(out->source_md5, in->source_md5);
    return out;
}

void match_list_destroy(match_list_t *list)
{
    if (!list->items)
        return;

    while (list->headp.lh_first != NULL) /* Delete. */
    {
        match_data_free(list->headp.lh_first->match);
        struct entry * aux = list->headp.lh_first;
        LIST_REMOVE(list->headp.lh_first, entries);
        free(aux);
        list->items--;
    }

   free(list);
}

bool component_list_add(component_list_t *list, component_data_t *new_comp, bool (*val)(component_data_t *a, component_data_t *b), bool remove_a)
{
    if (!new_comp->url)
    {
        scanlog("Incomple component\n");
        component_data_free(new_comp);
        return false;
    }

    if (!list->headp.lh_first)
    {
        scanlog("first component in list\n");
        struct comp_entry *nn = calloc(1, sizeof(struct comp_entry)); /* Insert at the head. */
        LIST_INSERT_HEAD(&list->headp, nn, entries);
        nn->component = new_comp;
        list->items++;
        list->last_element = nn;
        list->last_element_aux = NULL;
        return true;
    }
    else if (val)
    {
        if (list->last_element && list->last_element->component && !val(list->last_element->component, new_comp))
        {
            if (list->items >= list->max_items)
                return false;
            
            struct comp_entry *nn = calloc(1, sizeof(struct comp_entry)); /* Insert after. */
            nn->component = new_comp; 
            LIST_INSERT_AFTER(list->last_element, nn, entries);
            list->last_element_aux = list->last_element;
            list->last_element = nn; 
            list->items++;
            return true;
        }
        struct comp_entry *np = list->headp.lh_first;
        for (; np->entries.le_next != NULL; np = np->entries.le_next)
        {
            if (!np->entries.le_next->entries.le_next)
                list->last_element_aux = np;

            if (val(np->component, new_comp))
            {
                break;
            }
        }

        struct comp_entry *nn = calloc(1, sizeof(struct comp_entry)); /* Insert after. */
        nn->component = new_comp; 
        LIST_INSERT_BEFORE(np, nn, entries);
       
        if (!np->entries.le_next)
        {
            list->last_element = np;
            list->last_element_aux = nn;
        }
        list->items++;

        if (remove_a && list->items > list->max_items)
        {
            component_data_free(list->last_element->component);
            list->last_element->component = NULL;
            if (list->last_element_aux)
            {
                free(list->last_element);
                list->last_element_aux->entries.le_next = NULL;
                list->last_element = list->last_element_aux;
                list->last_element_aux = NULL;
            }
         
            list->last_element->entries.le_next = NULL;
            list->items--;
        }
         return true;
    }
    else
    {
        scanlog("Component Add to list nc\n");
        struct comp_entry *nn = calloc(1, sizeof(struct comp_entry)); /* Insert after. */
        nn->component = new_comp;
        LIST_INSERT_AFTER(list->headp.lh_first, nn, entries);
        return true;
    }

    return false;
}

bool match_list_add(match_list_t *list, match_data_t *new_match, bool (*val)(match_data_t *a, match_data_t *b), bool remove_a)
{
    if (!new_match->component_list.match_ref)
    {
        component_list_init(&new_match->component_list, list->scan_ref->max_components_to_process);
        new_match->component_list.match_ref = new_match;
    }
    else
    {
        if (!new_match->component_list.headp.lh_first|| !new_match->component_list.headp.lh_first->component->release_date)
            return false;
       // printf("%s - ", new_match->component_list.headp.lh_first->component->release_date);
    }

    if (!list->headp.lh_first)
    {
        struct entry *nn = calloc(1, sizeof(struct entry)); /* Insert at the head. */
        LIST_INSERT_HEAD(&list->headp, nn, entries);
        nn->match = new_match;
        list->last_element = nn;
        list->last_element_aux = NULL;
        list->items = 1;
        return true;
    }
    else if (val)
    {
        bool inserted = false;

        if (list->last_element && !val(list->last_element->match, new_match))
        {
            if (!list->autolimit && list->items >= list->max_items)
                return false;
                
            struct entry *nn = calloc(1, sizeof(struct entry)); /* Insert after. */
            nn->match = new_match;
            LIST_INSERT_AFTER(list->last_element, nn, entries);
            list->last_element_aux = list->last_element;
            list->last_element = nn;
            list->items++;
            inserted = true;
        }
        
        struct entry *np = list->headp.lh_first;
        if (!inserted)
        {
            for (; np->entries.le_next != NULL; np = np->entries.le_next)
            {
                if (val(np->match, new_match))
                {
                    break;
                }

            }

            struct entry *nn = calloc(1, sizeof(struct entry)); /* Insert after. */
            nn->match = new_match;
            LIST_INSERT_BEFORE(np, nn, entries);
            list->items++;
            

            if (np->entries.le_next == NULL)
            {
                list->last_element_aux = nn;
                list->last_element = np;
            }
        }
        
        if (list->autolimit && (list->headp.lh_first->match->hits * 0.75 > list->last_element->match->hits))
        {
            
            np = list->headp.lh_first;
            for (; np->entries.le_next != NULL && (list->headp.lh_first->match->hits * 0.75 <= np->match->hits); np = np->entries.le_next)
            {

            }
            list->last_element = np;
            list->last_element_aux = NULL;
            while (list->last_element->entries.le_next != NULL) /* Delete. */
            {
                match_data_free(list->last_element->entries.le_next->match);
                struct entry * aux = list->last_element->entries.le_next;
                LIST_REMOVE(list->last_element->entries.le_next, entries);
                free(aux);
                list->items--;
            }
            list->last_element->entries.le_next = NULL;
        }
        else if (list->last_element && !list->autolimit && remove_a && (list->items > list->max_items))
        {           
            if(!list->last_element_aux)
            {
                for (list->last_element_aux = list->headp.lh_first; list->last_element_aux->entries.le_next->entries.le_next != NULL; list->last_element_aux = list->last_element_aux->entries.le_next);
            }
            
            if(list->last_element_aux)
            {
                match_data_free(list->last_element->match);
                LIST_REMOVE(list->last_element_aux->entries.le_next, entries);
                free(list->last_element);
                list->last_element = list->last_element_aux;
                list->items--;
            }
            list->last_element_aux = NULL;
            list->last_element->entries.le_next = NULL;
        }

        scanlog("Add to list add: %d\n", list->items);
        return true;
    }
    else
    {
        scanlog("Add to list nc\n");
        struct entry *nn = calloc(1,sizeof(struct entry)); /* Insert after. */
        nn->match = new_match;
        LIST_INSERT_AFTER(list->headp.lh_first, nn, entries);
        list->items++;
    }

    return true;
}

void match_list_debug(match_list_t *list)
{
    int i = 0;
    scanlog("Print list\n");
    for (struct entry *np = list->headp.lh_first; np != NULL; np = np->entries.le_next)
    {
        char md5_hex[MD5_LEN * 2 + 1];
        ldb_bin_to_hex(np->match->matchmap_reg, MD5_LEN, md5_hex);
        //   printf("Item: %d - hits: %d - md5: %s - file: %s - release_date: %s - ranges: %s - purl:%s\n",
        // i, np->match->hits, md5_hex, np->match->file, np->match->release_date, np->match->line_ranges, np->match->purls[0]);
        printf("\nItem: %d - hits: %d - md5: %s - release: %s \n", i, np->match->hits, md5_hex, np->match->component_list.headp.lh_first->component->release_date);
        i++;
    }
}

void match_list_print(match_list_t *list, bool (*printer)(match_data_t *fpa), char *separator)
{
    bool first = true;
    int i = 0;
    for (struct entry *np = list->headp.lh_first; np != NULL && i<list->items; np = np->entries.le_next)
    {
        if (!np->match->component_list.items)
            continue;
        
        if (separator && !first)
        {
            printf("%s", separator);
        }
        
        printer(np->match);
        i++;
        first = false;
    }
}

void component_list_print(component_list_t *list, bool (*printer)(component_data_t *fpa), char *separator)
{
    for (struct comp_entry *np = list->headp.lh_first; np != NULL; np = np->entries.le_next)
    {
        if (printer(np->component))
            break;

        if (separator && np->entries.le_next && np->entries.le_next->component)
            printf("%s", separator);
    }
}

void match_list_process(match_list_t *list, bool (*funct_p)(match_data_t *fpa, void * fpb))
{
    for (struct entry *np = list->headp.lh_first; np != NULL; np = np->entries.le_next)
    {
        bool result = funct_p(np->match, (void*) list->scan_ref);

        if (result)
            break;
    }
}

bool match_list_is_empty(match_list_t *list)
{
    return (list->headp.lh_first != NULL);
}

bool component_date_comparation(component_data_t * a, component_data_t * b)
{
    if (!*b->release_date)
        return false;
    if (!*a->release_date)
        return true;
    /*if the relese date is the same untie with the component age (purl)*/
    if (!strcmp(b->release_date, a->release_date) && b->age > a->age)
        return true;
    /*select the oldest release date */
    if (strcmp(b->release_date, a->release_date) < 0)
		return true;
    
    return false;
}

