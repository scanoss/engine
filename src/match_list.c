#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "match_list.h"
#include <ldb.h>
#include "debug.h"

struct entry *nn, *nmax, *nmin, *n1, *n2, *np;

int list_size = 0;

struct listhead * match_list_init()
{
    struct listhead * head_new = malloc(sizeof(*head_new));
    LIST_INIT(head_new);                       /* Initialize the list. */
    return head_new;
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

void match_list_destroy(struct listhead * list)
{
    while (list->lh_first != NULL)           /* Delete. */
    {
        match_data_free(list->lh_first->match);
        LIST_REMOVE(list->lh_first, entries);
    }

     free(list);
}

bool match_list_add(struct listhead * list, match_data_t * new_match, bool (* val) (match_data_t * a, match_data_t * b), bool remove_a)
{
    if (!list->lh_first)
    {
        scanlog("Init List\n");
        nn = malloc(sizeof(struct entry));      /* Insert at the head. */
        LIST_INSERT_HEAD(list, nn, entries);
        nn->match = new_match;
        return true;
    }
    else if (val)
    {
        for (np = list->lh_first; np != NULL; np = np->entries.le_next)
        {
            if (val(np->match, new_match))
            {
                nn = malloc(sizeof(struct entry));      /* Insert after. */
                nn->match = new_match;
                LIST_INSERT_BEFORE(np, nn, entries);
                if (remove_a)
                    LIST_REMOVE(np, entries);

                return true;
            }
        }
    }
    else
    {
        scanlog("Add to list nc\n");
        nn = malloc(sizeof(struct entry));      /* Insert after. */
        nn->match = new_match;
        LIST_INSERT_AFTER(list->lh_first, nn, entries);
        return true;   
    }

    return false;
}

void match_list_debug(struct listhead * list)
{
    int i = 0;
    scanlog("Print list\n");
	for (np = list->lh_first; np != NULL; np = np->entries.le_next)
    {
        char md5_hex[MD5_LEN * 2 + 1];
        ldb_bin_to_hex(np->match->matchmap_reg, MD5_LEN, md5_hex);
        printf("Item: %d - hits: %d - md5: %s - file: %s - release_date: %s - ranges: %s - purl:%s\n", 
        i, np->match->hits, md5_hex, np->match->file, np->match->release_date, np->match->line_ranges, np->match->purls[0]);
         //printf("Item: %d - hits: %d - md5: %s\n", i, np->match->hits, md5_hex);
        i++;
	}   
}

void match_list_print(struct listhead * list, bool (*printer) (match_data_t * fpa), char * separator)
{
    for (np = list->lh_first; np != NULL; np = np->entries.le_next)
    {
        if (printer(np->match))
            break;

        if (separator && np->entries.le_next)
            printf("%s",separator);
        
    }
}


void match_list_process(struct listhead * list, bool (*funct_p) (match_data_t * fpa))
{
    for (np = list->lh_first; np != NULL; np = np->entries.le_next)
    {
        bool result = funct_p(np->match);
        
        if (!np->match->url)
        {
            scanlog("Removed element\n");
            LIST_REMOVE(np, entries);
        }

        if (result)
            break;
    }
}


bool match_list_is_empty(struct listhead * list)
{
    return (list->lh_first != NULL);
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
