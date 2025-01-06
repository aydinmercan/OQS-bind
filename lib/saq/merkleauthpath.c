#include <saq/merkleauthpath.h>
#include <saq/merklenode.h>

#include <arpa/inet.h>
#include <string.h>

static void
SAQ__authentication_node_free(void *p);

SAQ_STATUS
SAQ_authentication_node_new(SAQ_hash_cb_ptr hash_cb,
                            unsigned char *sibling_hash,
                            uint64_t sibling_hash_len, bool is_left,
                            SAQ_authentication_node_t **out) {
    SAQ_authentication_node_t *n = NULL;
    if ((out == NULL) || (sibling_hash_len == 0 && sibling_hash != NULL)
        || (sibling_hash_len != 0 && sibling_hash == NULL)) {
        goto err;
    }
    n = malloc(sizeof(SAQ_authentication_node_t));
    if (n == NULL) {
        goto err;
    }
    n->hash_cb = hash_cb;
    if (sibling_hash != NULL) {
        n->sibling_hash = malloc(sibling_hash_len);
        if (n->sibling_hash == NULL) {
            goto err;
        }
        memcpy(n->sibling_hash, sibling_hash, sibling_hash_len);
    }
    n->sibling_hash_len = sibling_hash_len;
    n->is_left = is_left;
    *out = n;
    return SAQ_SUCCESS;
err:
    SAQ__authentication_node_free(n);
    return SAQ_FAILURE;
}

static void
SAQ__authentication_node_free(void *p) {
    if (p == NULL) {
        return;
    }
    SAQ_authentication_node_t *node = (SAQ_authentication_node_t *)p;
    if (node->sibling_hash != NULL) {
        free(node->sibling_hash);
    }
    free(node);
}

SAQ_STATUS
SAQ_authentication_node_destroy(SAQ_authentication_node_t *node) {
    SAQ__authentication_node_free(node);
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_authentication_path_get_node(SAQ_authentication_path_t *ap,
                                 SAQ_authentication_node_t **out) {
    if (ap == NULL || out == NULL || *out != NULL) {
        return SAQ_FAILURE;
    }
    return SAQ_list_get_cur(ap, (void **)out);
}

SAQ_STATUS
SAQ_authentication_path_destroy(SAQ_authentication_path_t **ap) {
    SAQ_list_destroy(ap, SAQ__authentication_node_free);
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_authentication_path_prove(unsigned char *data, uint64_t data_len,
                              unsigned char *root_hash, uint64_t root_hash_len,
                              SAQ_authentication_path_t *ap) {
    if (ap == NULL) {
        return SAQ_FAILURE;
    }
    unsigned char *left_hash = NULL, *right_hash = NULL;
    uint64_t left_hash_len = 0, right_hash_len = 0;
    SAQ_authentication_node_t *cur_node = NULL;
    if (SAQ_authentication_path_go_first(ap) != SAQ_SUCCESS) {
        return SAQ_FAILURE;
    }
    if (SAQ_authentication_path_get_node(ap, &cur_node) != SAQ_SUCCESS) {
        return SAQ_FAILURE;
    }
    SAQ_hash_cb_ptr hash = cur_node->hash_cb;
    uint64_t cur_hash_len = cur_node->sibling_hash_len;
    unsigned char *cur_hash = malloc(cur_hash_len);
    if (cur_hash == NULL) {
        return SAQ_FAILURE;
    }
    hash(data, data_len, cur_hash, &cur_hash_len);
    cur_node = NULL;
    while (SAQ_authentication_path_get_node(ap, &cur_node) == SAQ_SUCCESS) {
        if (cur_node->sibling_hash == NULL) {
            goto err;
        }
        if (cur_node->is_left) {
            left_hash = cur_node->sibling_hash;
            left_hash_len = cur_node->sibling_hash_len;
            right_hash = cur_hash;
            right_hash_len = cur_hash_len;
        } else {
            left_hash = cur_hash;
            left_hash_len = cur_hash_len;
            right_hash = cur_node->sibling_hash;
            right_hash_len = cur_node->sibling_hash_len;
        }
    	unsigned char *combined_hash = malloc(left_hash_len + right_hash_len);
        if (combined_hash == NULL) {
	    goto err;
        }
        memcpy(combined_hash, left_hash, left_hash_len);
        memcpy(combined_hash + left_hash_len, right_hash, right_hash_len);
        hash(combined_hash, left_hash_len + right_hash_len, cur_hash,
             &cur_hash_len);
        free(combined_hash);
        if (SAQ_authentication_path_go_next(ap) == SAQ_FAILURE) {
            if (root_hash_len != cur_hash_len) {
                goto err;
            }
            if (memcmp(root_hash, cur_hash, cur_hash_len) == 0) {
                free(cur_hash);
                return SAQ_SUCCESS;
            } else {
                goto err;
            }
        }
        cur_node = NULL;
    }

err:
    if (cur_hash != NULL) {
        free(cur_hash);
    }
    return SAQ_FAILURE;
}

SAQ_STATUS
SAQ_authentication_node_byte_size(SAQ_authentication_node_t *n,
                                  uint64_t *size) {
    if (n == NULL || size == NULL) {
	if (size != NULL) {
		*size = 0;
	}
        return SAQ_FAILURE;
    }
    *size = sizeof(uint8_t) + sizeof(uint64_t) + n->sibling_hash_len;
    return SAQ_SUCCESS;
}

#include <assert.h>
SAQ_STATUS
SAQ_authentication_node_serialize(SAQ_authentication_node_t *n,
                                  unsigned char *out, uint64_t *out_len) {
    if (n == NULL || out == NULL || out_len == NULL) {
        if (out_len != NULL) {
            *out_len = 0;
        }
        return SAQ_FAILURE;
    }
    uint64_t len;
    if (SAQ_authentication_node_byte_size(n, &len) != SAQ_SUCCESS) {
        *out_len = 0;
        return SAQ_FAILURE;
    }
    if (*out_len < len) {
        *out_len = 0;
        return SAQ_FAILURE;
    }
    uint64_t h_len = 0;
    h_len = htonll(n->sibling_hash_len);
    assert(ntohll(h_len) == 16);
    memcpy(out, &(n->is_left), sizeof(uint8_t));
    memcpy(out + sizeof(uint8_t), &h_len, sizeof(uint64_t));
    memcpy(out + sizeof(uint8_t) + sizeof(uint64_t), n->sibling_hash,
           n->sibling_hash_len);

    *out_len = len;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_authentication_node_deserialize(unsigned char *in, uint64_t in_len,
                                    SAQ_hash_cb_ptr hash_cb,
                                    SAQ_authentication_node_t **out) {
    if (in == NULL || out == NULL || *out != NULL) {
        return SAQ_FAILURE;
    }
    if (in_len < sizeof(uint8_t) + sizeof(uint64_t)) {
        return SAQ_FAILURE;
    }
    SAQ_authentication_node_t *n = malloc(sizeof(SAQ_authentication_node_t));
    if (n == NULL) {
        return SAQ_FAILURE;
    }
    unsigned char *hash;
    n->is_left = *(uint8_t *)in;
    in += sizeof(uint8_t);
    in_len -= sizeof(uint8_t);
    uint64_t hash_len = ntohll(*(uint64_t *)in);
    in += sizeof(uint64_t);
    in_len -= sizeof(uint64_t);
    if (in_len < hash_len) {
        free(n);
        return SAQ_FAILURE;
    }
    hash = malloc(hash_len);
    if (hash == NULL) {
        free(n);
        return SAQ_FAILURE;
    }
    memcpy(hash, in, hash_len);
    n->hash_cb = hash_cb;
    n->sibling_hash = hash;
    n->sibling_hash_len = hash_len;
    *out = n;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_authentication_path_byte_size(SAQ_authentication_path_t *ap,
                                  uint64_t *size) {
    if (ap == NULL || size == NULL
          || SAQ_authentication_path_go_first(ap) != SAQ_SUCCESS) {
	if (size != NULL) {
		*size = 0;
	}
        return SAQ_FAILURE;
    }
    uint64_t byte_sum = 0;
    SAQ_authentication_node_t *n = NULL;
    while (SAQ_authentication_path_get_node(ap, &n) != SAQ_FAILURE) {
        uint64_t an_len = 0;
        if (SAQ_authentication_node_byte_size(n, &an_len) != SAQ_SUCCESS) {
            return SAQ_FAILURE;
        }
        byte_sum += an_len;
        if (SAQ_authentication_path_go_next(ap) != SAQ_SUCCESS) {
            break;
        }
        n = NULL;
    }
    *size = sizeof(uint32_t) + byte_sum;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_authentication_path_serialize(SAQ_authentication_path_t *ap,
                                  unsigned char *out, uint64_t *out_len) {
    if (ap == NULL || out == NULL || out_len == NULL) {
        if (out_len != NULL) {
            *out_len = 0;
        }
        return SAQ_FAILURE;
    }
    uint64_t len;
    if (SAQ_authentication_path_byte_size(ap, &len) != SAQ_SUCCESS) {
        *out_len = 0;
        return SAQ_FAILURE;
    }
    if (*out_len < len) {
        *out_len = 0;
        return SAQ_FAILURE;
    }
    *out_len = len;
    memset(out, 0, len);
    uint32_t ap_len = 1;
    if (SAQ_authentication_path_go_first(ap) != SAQ_SUCCESS) {
        return SAQ_FAILURE;
    }
    while (SAQ_authentication_path_go_next(ap) == SAQ_SUCCESS) {
        ap_len++;
    }
    ap_len = htonl(ap_len);
    memcpy(out, &ap_len, sizeof(uint32_t));
    out += sizeof(uint32_t);
    len -= sizeof(uint32_t);
    if (SAQ_authentication_path_go_first(ap) != SAQ_SUCCESS) {
        return SAQ_FAILURE;
    }
    SAQ_authentication_node_t *n = NULL;
    while (SAQ_authentication_path_get_node(ap, &n) == SAQ_SUCCESS) {
        uint64_t ol = len;
        if (SAQ_authentication_node_serialize(n, out, &ol) != SAQ_SUCCESS) {
            *out_len = 0;
            return SAQ_FAILURE;
        }
        out += ol;
        len -= ol;
        if (SAQ_authentication_path_go_next(ap) != SAQ_SUCCESS) {
            break;
        }
        n = NULL;
    }

    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_authentication_path_deserialize(unsigned char *in, uint64_t in_len,
                                    SAQ_hash_cb_ptr hash_cb,
                                    SAQ_authentication_path_t **out) {
    if (in == NULL || hash_cb == NULL || out == NULL || *out != NULL) {
        return SAQ_FAILURE;
    }
    if (in_len < sizeof(uint32_t)) {
        return SAQ_FAILURE;
    }

    uint32_t ap_len = ntohl(*(uint32_t *)in);
    in += sizeof(uint32_t);
    in_len -= sizeof(uint32_t);

    SAQ_authentication_path_t *ap = NULL;
    if (SAQ_authentication_path_init(&ap) != SAQ_SUCCESS) {
        return SAQ_FAILURE;
    }
    for (uint32_t i = 0; i < ap_len; i++) {
        SAQ_authentication_node_t *n = NULL;
        uint64_t byte_size;
        if (SAQ_authentication_node_deserialize(in, in_len, hash_cb, &n)
            != SAQ_SUCCESS) {
            SAQ_authentication_path_destroy(&ap);
            return SAQ_FAILURE;
        }
        if (SAQ_authentication_node_byte_size(n, &byte_size) != SAQ_SUCCESS) {
            SAQ_authentication_path_destroy(&ap);
            return SAQ_FAILURE;
        }
        in += byte_size;
        in_len -= byte_size;
        SAQ_authentication_path_append(ap, (void *)n);
    }
    *out = ap;
    return SAQ_SUCCESS;
}
