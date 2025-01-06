#include <saq/merklenode.h>

#include <arpa/inet.h>
#include <string.h>


SAQ_STATUS
SAQ_merkle_node_new(SAQ_hash_cb_ptr hash_cb, SAQ_merkle_node_t *left,
                    SAQ_merkle_node_t *right, unsigned char *data,
                    uint64_t data_len, SAQ_merkle_node_t **out) {

    if (out == NULL || *out != NULL) {
        return SAQ_FAILURE;
    }
    SAQ_merkle_node_t *n = malloc(sizeof(SAQ_merkle_node_t));
    if (n == NULL) {
        return SAQ_FAILURE;
    }
    n->hash_cb = hash_cb;
    n->left = left;
    n->right = right;
    n->parent = NULL;

    unsigned char *hash = NULL;
    uint64_t hash_len;
    if (data != NULL) {
        // First call to get the length of the digest
        if (n->hash_cb(data, data_len, NULL, &hash_len) != SAQ_FAILURE) {
            free(n);
            return SAQ_FAILURE;
        }
        hash = malloc(hash_len);
        if (hash == NULL) {
            free(n);
            return SAQ_FAILURE;
        }
        if (n->hash_cb(data, data_len, hash, &hash_len) != SAQ_SUCCESS) {
            free(n);
	    free(hash);
            return SAQ_FAILURE;
        }
    } else {
        SAQ_STATUS ret = SAQ_SUCCESS;
        unsigned char *left_hash = NULL;
        uint64_t left_len = 0;
        unsigned char *right_hash = NULL;
        uint64_t right_len = 0;
        unsigned char *combined_hash = NULL;
        if (left == NULL || right == NULL) {
            ret = SAQ_FAILURE;
            goto combined_cleanup;
        }
        if (SAQ_merkle_node_get_hash_len(left, &left_len) != SAQ_SUCCESS
            || SAQ_merkle_node_get_hash_len(right, &right_len) != SAQ_SUCCESS) {
            ret = SAQ_FAILURE;
            goto combined_cleanup;
        }
        left_hash = malloc(left_len);
        right_hash = malloc(right_len);
        if (left_hash == NULL || right_hash == NULL) {
            ret = SAQ_FAILURE;
            goto combined_cleanup;
        }

        if (SAQ_merkle_node_get_hash(left, left_hash, &left_len) != SAQ_SUCCESS
            || SAQ_merkle_node_get_hash(right, right_hash, &right_len)
                   != SAQ_SUCCESS) {
            ret = SAQ_FAILURE;
            goto combined_cleanup;
        }

        combined_hash = malloc(left_len + right_len);
        if (combined_hash == NULL) {
            ret = SAQ_FAILURE;
            goto combined_cleanup;
        }
        memcpy(combined_hash, left_hash, left_len);
        memcpy(combined_hash + left_len, right_hash, right_len);
        if (n->hash_cb(combined_hash, left_len + right_len, NULL, &hash_len)
            != SAQ_FAILURE) {
            ret = SAQ_FAILURE;
            goto combined_cleanup;
        }
        hash = malloc(hash_len);
        if (hash == NULL) {
            ret = SAQ_FAILURE;
            goto combined_cleanup;
        }
        if (n->hash_cb(combined_hash, left_len + right_len, hash, &hash_len)
            != SAQ_SUCCESS) {
            ret = SAQ_FAILURE;
        }

    combined_cleanup:
        if (left_hash != NULL) {
            free(left_hash);
        }
        if (right_hash != NULL) {
            free(right_hash);
        }
        if (combined_hash != NULL) {
            free(combined_hash);
        }
        if (ret == SAQ_FAILURE) {
            free(n);
	    if (hash != NULL) {
	    	free(hash);
	    }
            return SAQ_FAILURE;
        }
    }
    n->hash = hash;
    n->hash_len = hash_len;

    *out = n;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_node_get_hash_len(SAQ_merkle_node_t *node, uint64_t *hash_len) {
    if (node == NULL || hash_len == NULL) {
        return SAQ_FAILURE;
    }
    *hash_len = node->hash_len;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_node_get_hash(SAQ_merkle_node_t *node, unsigned char *hash,
                         uint64_t *hash_len) {
    if (hash == NULL || hash_len == NULL || node == NULL
        || *hash_len < node->hash_len) {
        return SAQ_FAILURE;
    }

    memcpy(hash, node->hash, node->hash_len);
    *hash_len = node->hash_len;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_node_get_left(SAQ_merkle_node_t *node, SAQ_merkle_node_t **out) {
    if (out == NULL || *out != NULL || node == NULL) {
        return SAQ_FAILURE;
    }
    *out = node->left;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_node_get_right(SAQ_merkle_node_t *node, SAQ_merkle_node_t **out) {
    if (out == NULL || *out != NULL || node == NULL) {
        return SAQ_FAILURE;
    }
    *out = node->right;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_node_set_parent(SAQ_merkle_node_t *node, SAQ_merkle_node_t *parent) {
    if (node == NULL) {
        return SAQ_FAILURE;
    }
    node->parent = parent;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_node_get_parent(SAQ_merkle_node_t *node, SAQ_merkle_node_t **out) {
    if (out == NULL || node == NULL) {
        return SAQ_FAILURE;
    }
    *out = node->parent;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_node_copy(SAQ_merkle_node_t *in, SAQ_merkle_node_t **out) {
    if (out == NULL || *out != NULL) {
        return SAQ_FAILURE;
    }
    if (in == NULL) {
        *out = NULL;
        return SAQ_SUCCESS;
    }

    SAQ_merkle_node_t *n = malloc(sizeof(SAQ_merkle_node_t));
    if (n == NULL) {
        return SAQ_FAILURE;
    }

    n->hash = malloc(in->hash_len);
    if (n->hash == NULL) {
        free(n);
        return SAQ_FAILURE;
    }
    memcpy(n->hash, in->hash, in->hash_len);
    n->hash_len = in->hash_len;
    n->left = in->left;
    n->right = in->right;
    n->parent = in->parent;
    n->hash_cb = in->hash_cb;
    *out = n;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_node_destroy(SAQ_merkle_node_t *node) {
    if (node == NULL) {
        return SAQ_SUCCESS;
    }
    if (node->hash != NULL) {
        free(node->hash);
    }
    free(node);
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_node_byte_size(SAQ_merkle_node_t *n, uint64_t *size) {
    if (n == NULL || size == NULL) {
	if (size != NULL) {
		*size = 0;
	}
        return SAQ_FAILURE;
    }
    *size = sizeof(uint64_t) + n->hash_len;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_node_serialize(SAQ_merkle_node_t *n, unsigned char *out,
                          uint64_t *out_len) {
    if (n == NULL || out == NULL || out_len == NULL) {
        if (out_len != NULL) {
            *out_len = 0;
        }
        return SAQ_FAILURE;
    }
    uint64_t len;
    if (SAQ_merkle_node_byte_size(n, &len) != SAQ_SUCCESS) {
        *out_len = 0;
        return SAQ_FAILURE;
    }
    if (len > *out_len) {
        *out_len = 0;
        return SAQ_FAILURE;
    }
    uint64_t hl = htonll(n->hash_len);
    memcpy(out, &hl, sizeof(uint64_t));
    memcpy(out + sizeof(uint64_t), n->hash, n->hash_len);
    *out_len = len;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_node_deserialize(unsigned char *in, uint64_t in_len,
                            SAQ_hash_cb_ptr hash_cb, SAQ_merkle_node_t **out) {
    if (in == NULL || out == NULL || *out != NULL) {
        return SAQ_FAILURE;
    }
    if (in_len < sizeof(uint64_t)) {
        return SAQ_FAILURE;
    }
    unsigned char *hash;
    uint64_t hash_len = ntohll(*(uint64_t *)in);
    in += sizeof(uint64_t);
    in_len -= sizeof(uint64_t);
    if (in_len < hash_len) {
        return SAQ_FAILURE;
    }
    hash = malloc(hash_len);
    if (hash == NULL) {
        return SAQ_FAILURE;
    }
    memcpy(hash, in, hash_len);
    SAQ_merkle_node_t *n = malloc(sizeof(SAQ_merkle_node_t));
    if (n == NULL) {
        free(hash);
        return SAQ_FAILURE;
    }
    n->hash_cb = hash_cb;
    n->left = NULL;
    n->right = NULL;
    n->parent = NULL;
    n->hash = hash;
    n->hash_len = hash_len;
    *out = n;
    return SAQ_SUCCESS;
}
