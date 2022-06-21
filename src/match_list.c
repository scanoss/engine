#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "match_list.h"
#include <ldb.h>
#include "debug.h"

struct entry *nn, *nmax, *nmin, *n1, *n2, *np;

int list_size = 0;

match_list_t * match_list_init()
{
    match_list_t * list_new = malloc(sizeof(*list_new));
    LIST_INIT(&list_new->headp);                       /* Initialize the list. */
    list_new->items = 0;
    list_new->max_items = 1;
    return list_new;
}

void match_data_free(match_data_t * data)
{
    if (!data)
        return;

    free(data->vendor);
	free(data->component);
	free (data->version);
	free (data-> release_date);
	free(data->latest_release_date);
	free (data->latest_version);
	free (data->license);
	free (data->url);
	free (data->file);
	free(data->line_ranges);
    free(data->main_url);
    free (data->oss_ranges);
    free(data->matched_percent);
    
    for (int i=0; i<MAX_PURLS; i++)
    {
        free (data->purls[i]);
        free(data->purls_md5[i]);
    }
}

void match_list_destroy(match_list_t * list)
{
    while (list->headp.lh_first != NULL)           /* Delete. */
    {
        match_data_free(list->headp.lh_first->match);
        LIST_REMOVE(list->headp.lh_first, entries);
        list->items--;
    }

     free(list);
}

bool match_list_add(match_list_t * list, match_data_t * new_match, bool (* val) (match_data_t * a, match_data_t * b), bool remove_a)
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
        nn = malloc(sizeof(struct entry));      /* Insert at the head. */
        LIST_INSERT_HEAD(&list->headp, nn, entries);
        nn->match = new_match;
        list->items = 1;
        return true;
    }
    else if (val)
    {
        for (np = list->headp.lh_first; np != NULL; np = np->entries.le_next)
        {
            if (val(np->match, new_match))
            {
                nn = malloc(sizeof(struct entry));      /* Insert after. */
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
        nn = malloc(sizeof(struct entry));      /* Insert after. */
        nn->match = new_match;
        LIST_INSERT_AFTER(list->headp.lh_first, nn, entries);
        return true;   
    }

    return false;
}

void match_list_debug(match_list_t * list)
{
    int i = 0;
    scanlog("Print list\n");
	for (np = list->headp.lh_first; np != NULL; np = np->entries.le_next)
    {
        char md5_hex[MD5_LEN * 2 + 1];
        ldb_bin_to_hex(np->match->matchmap_reg, MD5_LEN, md5_hex);
     //   printf("Item: %d - hits: %d - md5: %s - file: %s - release_date: %s - ranges: %s - purl:%s\n", 
       // i, np->match->hits, md5_hex, np->match->file, np->match->release_date, np->match->line_ranges, np->match->purls[0]);
         printf("Item: %d - hits: %d - md5: %s\n", i, np->match->hits, md5_hex);
        i++;
	}   
}

void match_list_print(match_list_t * list, bool (*printer) (match_data_t * fpa), char * separator)
{
    for (np = list->headp.lh_first; np != NULL; np = np->entries.le_next)
    {
        if (printer(np->match))
            break;

        if (separator && np->entries.le_next)
            printf("%s",separator);
        
    }
}


void match_list_process(match_list_t * list, bool (*funct_p) (match_data_t * fpa))
{
    for (np = list->headp.lh_first; np != NULL; np = np->entries.le_next)
    {
        bool result = funct_p(np->match);
        
        if (!np->match->url)
        {
            scanlog("Removed element\n");
            LIST_REMOVE(np, entries);
            list->items--;
        }

        if (result)
            break;
    }
}


bool match_list_is_empty(match_list_t * list)
{
    return (list->headp.lh_first != NULL);
}

// void list_test()
// {
	
// 	n1 = malloc(sizeof(struct entry));      /* Insert at the head. */
// 	LIST_INSERT_HEAD(&head, n1, entries);

// 	n2 = malloc(sizeof(struct entry));      /* Insert after. */
// 	LIST_INSERT_AFTER(n1, n2, entries);
//                                         /* Forward traversal. */
// 	for (np = head.lh_first; np != NULL; np = np->entries.le_next)
//     {
// 		np->p1 = 0;
// 		np->p2 = 1;
// 	}
	
// 	for (np = head.lh_first; np != NULL; np = np->entries.le_next)
//     {
// 		np->p1++;
// 		np->p2++;
// 	}
// 	int i = 0;
// 	for (np = head.lh_first; np != NULL; np = np->entries.le_next)
//     {
// 		printf("Element %d, p1: %d p2 %d\n", i, np->p1, np->p2);
// 		i++;
// 	}

// 	while (head.lh_first != NULL)           /* Delete. */
//     	LIST_REMOVE(head.lh_first, entries);
// }
/****************************************************/
