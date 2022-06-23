#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "match_list.h"
#include <ldb.h>
#include "debug.h"

int list_size = 0;

void component_data_free(component_data_t *data)
{
    free(data->vendor);
    free(data->component);
    free(data->version);
    free(data->release_date);
    free(data->latest_release_date);
    free(data->latest_version);
    free(data->license);
    free(data->url);
    free(data->file);
    free(data->main_url);

    for (int i = 0; i < MAX_PURLS; i++)
    {
        free(data->purls[i]);
        free(data->purls_md5[i]);
    }
}

void component_list_destroy(component_list_t *list)
{
    while (list->headp.lh_first != NULL) /* Delete. */
    {
        component_data_free(list->headp.lh_first->component);
        LIST_REMOVE(list->headp.lh_first, entries);
        list->items--;
    }
}

void component_list_init(component_list_t *comp_list)
{
    scanlog("Init component list\n");
    LIST_INIT(&comp_list->headp); /* Initialize the list. */
    comp_list->items = 0;
    comp_list->max_items = 3;
}

match_list_t *match_list_init()
{
    match_list_t *list_new = malloc(sizeof(*list_new));
    LIST_INIT(&list_new->headp); /* Initialize the list. */
    list_new->items = 0;
    list_new->max_items = 3;

    return list_new;
}

void match_data_free(match_data_t *data)
{
    if (!data)
        return;

    free(data->line_ranges);
    free(data->oss_ranges);
    free(data->matched_percent);

    component_list_destroy(&data->component_list);
}

void match_list_destroy(match_list_t *list)
{
    while (list->headp.lh_first != NULL) /* Delete. */
    {
        match_data_free(list->headp.lh_first->match);
        LIST_REMOVE(list->headp.lh_first, entries);
        list->items--;
    }

    free(list);
}

bool component_list_add(component_list_t *list, component_data_t *new_comp, bool (*val)(component_data_t *a, component_data_t *b), bool remove_a)
{
    scanlog("add component list function\n");

    if (!new_comp->url)
    {
        scanlog("Incomple component\n");
        component_data_free(new_comp);
    }

    if (!list->headp.lh_first)
    {
        scanlog("first component in list\n");
        struct comp_entry *nn = calloc(1, sizeof(struct comp_entry)); /* Insert at the head. */
        LIST_INSERT_HEAD(&list->headp, nn, entries);
        nn->component = new_comp;
        list->items = 1;
        return true;
    }
    else if (val)
    {
        for (struct comp_entry *np = list->headp.lh_first; np != NULL; np = np->entries.le_next)
        {
            if (val(np->component, new_comp))
            {
                scanlog("Component Add to list\n");
                struct comp_entry *nn = calloc(1, sizeof(struct comp_entry)); /* Insert after. */
                nn->component = new_comp;
                LIST_INSERT_BEFORE(np, nn, entries);
                if (remove_a && list->items == list->max_items)
                    LIST_REMOVE(np, entries);
                else
                    list->items++;

                return true;
            }
        }
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
    /*if (list->items + 1 > list->max_items)
    {
        scanlog("Max items reached");
        match_data_free(new_match);
        return false;
    }*/

    if (!list->headp.lh_first)
    {
        scanlog("Init List\n");
        struct entry *nn = malloc(sizeof(struct entry)); /* Insert at the head. */
        LIST_INSERT_HEAD(&list->headp, nn, entries);
        component_list_init(&new_match->component_list);
        nn->match = new_match;
        list->items = 1;
        return true;
    }
    else if (val)
    {
        for (struct entry *np = list->headp.lh_first; np != NULL; np = np->entries.le_next)
        {
            if (val(np->match, new_match))
            {
                struct entry *nn = malloc(sizeof(struct entry)); /* Insert after. */
                component_list_init(&new_match->component_list);
                nn->match = new_match;
                LIST_INSERT_BEFORE(np, nn, entries);
                if (remove_a && list->items == list->max_items)
                    LIST_REMOVE(np, entries);
                else
                    list->items++;

                return true;
            }
        }
    }
    else
    {
        scanlog("Add to list nc\n");
        struct entry *nn = malloc(sizeof(struct entry)); /* Insert after. */
        component_list_init(&new_match->component_list);
        nn->match = new_match;
        LIST_INSERT_AFTER(list->headp.lh_first, nn, entries);
        return true;
    }

    return false;
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
        printf("Item: %d - hits: %d - md5: %s\n", i, np->match->hits, md5_hex);
        i++;
    }
}

void match_list_print(match_list_t *list, bool (*printer)(match_data_t *fpa), char *separator)
{
    for (struct entry *np = list->headp.lh_first; np != NULL; np = np->entries.le_next)
    {
        if (!np->match->component_list.items)
            continue;
        
        if (separator && np != list->headp.lh_first)
            printf("%s", separator);
         
         printer(np->match);
    }
}

void component_list_print(component_list_t *list, bool (*printer)(component_data_t *fpa), char *separator)
{
    for (struct comp_entry *np = list->headp.lh_first; np != NULL; np = np->entries.le_next)
    {
        if (printer(np->component))
            break;

        if (separator && np->entries.le_next)
            printf("%s", separator);
    }
}

void match_list_process(match_list_t *list, bool (*funct_p)(match_data_t *fpa))
{
    for (struct entry *np = list->headp.lh_first; np != NULL; np = np->entries.le_next)
    {
        bool result = funct_p(np->match);

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
	/*printf("<<%s, %s>>\n", b->release_date, a->release_date);
    if (!b->release_date || a->release_date)
    {
        scanlog("error: incomplete component\n");
        return false;
    }*/
    if (strcmp(b->release_date, a->release_date) <= 0)
	{
		return true;
	}
    return false;
}