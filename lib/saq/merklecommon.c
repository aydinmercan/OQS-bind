#include <saq/merklecommon.h>

SAQ_STATUS
SAQ_list_init(SAQ_list_t **l) {
    if (l == NULL || *l != NULL) {
        return SAQ_FAILURE;
    }
    SAQ_list_t *newlist = malloc(sizeof(SAQ_list_t));
    if (newlist == NULL) {
        return SAQ_FAILURE;
    }
    newlist->head = NULL;
    newlist->tail = NULL;
    newlist->cur = NULL;
    *l = newlist;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_list_go_first(SAQ_list_t *n) {
    if (n == NULL || n->head == NULL) {
        return SAQ_FAILURE;
    }
    n->cur = n->head;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_list_go_next(SAQ_list_t *n) {
    if (n == NULL || n->cur == NULL || n->cur->next == NULL) {
        return SAQ_FAILURE;
    }
    n->cur = n->cur->next;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_list_get_cur(SAQ_list_t *n, void **out) {
    if (n == NULL || out == NULL || n->cur == NULL) {
        return SAQ_FAILURE;
    }
    *out = n->cur->data;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_list_append(SAQ_list_t *l, void *d) {
    if (l == NULL) {
        return SAQ_FAILURE;
    }
    SAQ_list_node_t *n = malloc(sizeof(SAQ_list_node_t));
    if (n == NULL) {
        return SAQ_FAILURE;
    }
    n->data = d;
    n->next = NULL;
    if (l->head == NULL) {
        l->head = n;
        l->tail = n;
        l->cur = n;
        return SAQ_SUCCESS;
    } else {
        l->tail->next = n;
        l->tail = n;
        return SAQ_SUCCESS;
    }
}

void
SAQ_list_destroy(SAQ_list_t **l, void (*free_cb)(void *)) {
    if (l == NULL || *l == NULL) {
        return;
    }
    SAQ_list_t *list = *l;
    
    SAQ_list_node_t *n = list->head;
    while (n != NULL) {
        void *p = n->data;
        SAQ_list_node_t *c = n;
        if (free_cb != NULL) {
            free_cb(p);
        }
        n = n->next;
        free(c);
    }
    free(list);
    *l = NULL;
}
