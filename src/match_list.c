#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <ldb.h>
#include "match_list.h"
#include "debug.h"
#include "match.h"
#include "component.h"

int list_size = 0;
static float match_list_tolerance = MATCH_LIST_TOLERANCE;

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
    LIST_INIT(&comp_list->headp); /* Initialize the list. */
    comp_list->items = 0;
    if (max_items)
        comp_list->max_items = max_items;
    else
        comp_list->autolimit = true;

    comp_list->last_element = NULL;
}

match_list_t * match_list_init(bool autolimit, int max_items)
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

    return list;
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
        scanlog("first component in list %s\n", new_comp->purls[0]);
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

        if (list->last_element && !list->autolimit && remove_a && (list->items > list->max_items))
        {           
            if(!list->last_element_aux)
            {
                for (list->last_element_aux = list->headp.lh_first; list->last_element_aux->entries.le_next->entries.le_next != NULL; list->last_element_aux = list->last_element_aux->entries.le_next);
            }
            
            if(list->last_element_aux)
            {
                component_data_free(list->last_element->component);
                LIST_REMOVE(list->last_element_aux->entries.le_next, entries);
                free(list->last_element);
                list->last_element = list->last_element_aux;
                list->items--;
            }
            list->last_element_aux = NULL;
            list->last_element->entries.le_next = NULL;
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

bool component_list_add_binary(component_list_t *list, component_data_t *new_comp, bool (*val)(component_data_t *a, component_data_t *b), bool remove_a)
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
        struct comp_entry *np = list->headp.lh_first;
        for (; np->entries.le_next != NULL; np = np->entries.le_next)
        {
            if (!np->entries.le_next->entries.le_next)
                list->last_element_aux = np;

            if (val(np->component, new_comp))
            {
                new_comp->hits = np->component->hits;
                return false;
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
        return true;
    }

    return false;
}

void match_list_tolerance_set(float in)
{
    if (in > 99)
        in = 99;
    
    match_list_tolerance = 100.0-in;
    scanlog("setting match list tolerance to %.1f\n", match_list_tolerance);
}

bool tolerance_eval(int a, int b)
{
    int relative_error = (abs(a - b) * 100) / ((a + b) / 2);
    if (100 - relative_error >= match_list_tolerance)
        return true;
    else
        return false;
}


/**
 * @brief Try to add a match in a existing matches list.
 * 
 * @param list pointer to match list object.
 * @param new_match new match to be inserted.
 * @param val pointer function to evaluate the position in the list.
 * @param remove_a true to remove the last item in the list if the list is full.
 * @return true if the new match was added.
 * @return false if the new match was rejected.
 */
bool match_list_add(match_list_t *list, match_data_t *new_match, bool (*val)(match_data_t *a, match_data_t *b), bool remove_a)
{
    /*Check if the match is present in another list*/
    if (!new_match->component_list.match_ref)
    {
        /*Is a new match, we have to initialize the component list */
        component_list_init(&new_match->component_list, new_match->scan_ower->max_components_to_process);
        new_match->component_list.match_ref = new_match;
    }
    else  
    {
        /*discard incomplete matches*/
        if (!new_match->component_list.headp.lh_first|| !new_match->component_list.headp.lh_first->component->release_date)
            return false;
    }
    /*If the list is empty, add as first element*/
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
    else if (val) /* check is the function pointer is defined */
    {
        bool inserted = false;
        /*evaluate against the last element*/
        if (list->last_element && !val(list->last_element->match, new_match))
        {
            /* if the list is full reject the new match */
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
            /*compare with the elements of the list*/
            for (; np->entries.le_next != NULL; np = np->entries.le_next)
            {
                if (val(np->match, new_match))
                {
                    break;
                }
            }
            /*insert in place */
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
        /* in autolimit mode the list doesnt have a fix size, it will accept all the matchest until a 75% of the fist element (the biggest) */
        //TODO: this part of the code should be in the function pointer or I need to re-evaluate the archtecture of this function */
        if (list->autolimit && !tolerance_eval(list->headp.lh_first->match->lines_matched, list->last_element->match->lines_matched))
        {    
            np = list->headp.lh_first;
            /*We have to find and remove the unwanted elements */
            for (; np->entries.le_next != NULL && tolerance_eval(list->headp.lh_first->match->lines_matched, np->entries.le_next->match->lines_matched); np = np->entries.le_next)
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
        /*If the list is in fixed size mode we have to remove the last element when the list is full and we add a new one*/
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
        ldb_bin_to_hex(np->match->matchmap_reg->md5, MD5_LEN, md5_hex);
        //   printf("Item: %d - hits: %d - md5: %s - file: %s - release_date: %s - ranges: %s - purl:%s\n",
        // i, np->match->hits, md5_hex, np->match->file, np->match->release_date, np->match->line_ranges, np->match->purls[0]);
        printf("\nItem: %d - hits: %d - md5: %s - release: %s \n", i, np->match->hits, md5_hex, np->match->component_list.headp.lh_first->component->release_date);
        i++;
    }
}

bool match_list_print(match_list_t *list, bool (*printer)(match_data_t *fpa), char *separator)
{
    bool first = true;
    int i = 0;
    bool printed = false;
    for (struct entry *np = list->headp.lh_first; np != NULL && i<list->items; np = np->entries.le_next)
    {
        if (!np->match->component_list.items)
            continue;
        
        if (separator && !first)
        {
            printf("%s", separator);
        }
        printed |= printer(np->match);
        i++;
        first = false;
    }
    if (!printed)
        return false;

    return true;
}

bool match_list_eval(match_list_t *list, match_data_t * in,  bool (*eval)(match_data_t *fpa, match_data_t *fpb))
{
    int i = 0;
    for (struct entry *np = list->headp.lh_first; np != NULL && i<list->items; np = np->entries.le_next)
    {
        if(eval(np->match, in))
            return true;
        i++;
    }
    return false;
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



