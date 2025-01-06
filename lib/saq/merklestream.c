#include <saq/merklestream.h>

#include <arpa/inet.h>
#include <string.h>
#include <math.h>


SAQ_STATUS
SAQ_merkle_stream_new(SAQ_hash_cb_ptr hash_cb, SAQ_merkle_stream_t **out) {
    if (hash_cb == NULL) {
        return SAQ_FAILURE;
    }
    SAQ_merkle_stream_t *ms = malloc(sizeof(SAQ_merkle_stream_t));
    if (ms == NULL) {
        return SAQ_FAILURE;
    }
    ms->root = NULL;
    ms->hash_cb = hash_cb;
    ms->data_nodes = NULL;
    if (SAQ_list_init(&(ms->data_nodes)) != SAQ_SUCCESS) {
        free(ms);
        return SAQ_FAILURE;
    }
    ms->data_node_count = 0;
    ms->tree_nodes = NULL;
    ms->tree_node_count = 0;
    *out = ms;
    return SAQ_SUCCESS;
}

static SAQ_STATUS
SAQ__merkle_stream_recursive_destroy(SAQ_merkle_node_t *root) {
    if (root == NULL) {
        return SAQ_SUCCESS;
    }
    SAQ_merkle_node_t *left = NULL;
    SAQ_merkle_node_t *right = NULL;
    SAQ_merkle_node_get_left(root, &left);
    SAQ_merkle_node_get_right(root, &right);

    SAQ__merkle_stream_recursive_destroy(left);
    SAQ__merkle_stream_recursive_destroy(right);
    // We will clean up these nodes when the data_nodes list is destroyed.
    if (left != NULL && right != NULL) {
        SAQ_merkle_node_destroy(root);
    }
    return SAQ_SUCCESS;
}

static void
SAQ__merkle_node_destroy(void *p) {
    SAQ_merkle_node_destroy(p);
}

SAQ_STATUS
SAQ_merkle_stream_destroy(SAQ_merkle_stream_t **in) {
    if (in == NULL || *in == NULL) {
        return SAQ_SUCCESS;
    }
    SAQ_merkle_stream_t *ms = *in;
    SAQ__merkle_stream_recursive_destroy(ms->root);
    if (ms->tree_nodes != NULL) {
        free(ms->tree_nodes);
        ms->tree_nodes = NULL;
    }
    SAQ_list_destroy(&(ms->data_nodes), SAQ__merkle_node_destroy);
    free(*in);
    *in = NULL;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_stream_write(SAQ_merkle_stream_t *s, unsigned char *data,
                        uint64_t data_len) {
    if (s == NULL) {
        return SAQ_FAILURE;
    }
    SAQ_merkle_node_t *n = NULL;
    if (SAQ_merkle_node_new(s->hash_cb, NULL, NULL, data, data_len, &n)
          != SAQ_SUCCESS) {
        return SAQ_FAILURE;
    }
    if (SAQ_list_append(s->data_nodes, n) != SAQ_SUCCESS) {
        SAQ_merkle_node_destroy(n);
        return SAQ_FAILURE;
    }
    s->data_node_count++;
    return SAQ_SUCCESS;
}

static SAQ_STATUS
SAQ__merkle_stream_recursive_build(SAQ_merkle_stream_t *ms, uint64_t start,
                                   uint64_t end, SAQ_merkle_node_t **out) {
    if (ms == NULL || out == NULL || *out != NULL ||
          start >= end || end > ms->tree_node_count) {
        return SAQ_FAILURE;
    }
    SAQ_merkle_node_t **tree_nodes = ms->tree_nodes;
    uint64_t tree_nodes_len = (end - start);
    uint64_t mid = tree_nodes_len / 2;
    SAQ_merkle_node_t *s = tree_nodes[start];
    if (tree_nodes_len == 1) {
        *out = s;
        return SAQ_SUCCESS;
    }
    SAQ_merkle_node_t *left = NULL;
    SAQ_merkle_node_t *right = NULL;
    if (SAQ__merkle_stream_recursive_build(ms, start, start + mid, &left)
        != SAQ_SUCCESS) {
        return SAQ_FAILURE;
    }
    if (SAQ__merkle_stream_recursive_build(ms, start + mid, end, &right)
        != SAQ_SUCCESS) {
        SAQ__merkle_stream_recursive_destroy(left);
        return SAQ_FAILURE;
    }
    SAQ_merkle_node_t *n = NULL;
    if (SAQ_merkle_node_new(ms->hash_cb, left, right, NULL, 0, &n)
        != SAQ_SUCCESS) {
        SAQ__merkle_stream_recursive_destroy(left);
        SAQ__merkle_stream_recursive_destroy(right);
        return SAQ_FAILURE;
    }

    if (SAQ_merkle_node_set_parent(left, n) != SAQ_SUCCESS
        || SAQ_merkle_node_set_parent(right, n) != SAQ_SUCCESS) {
        SAQ__merkle_stream_recursive_destroy(n);
        return SAQ_FAILURE;
    }
    *out = n;
    return SAQ_SUCCESS;
}

static SAQ_STATUS
SAQ_merkle_stream_finalize_until(SAQ_merkle_stream_t *s, uint64_t *until) {
    if (until != NULL && *until == 0) {
	return SAQ_SUCCESS;
    }
    if (s == NULL) {
        return SAQ_FAILURE;
    }
    if (s->tree_nodes != NULL) {
        free(s->tree_nodes);
    }
    uint64_t tree_node_count;
    uint64_t offset;
    if (until != NULL && *until < s->data_node_count) {
        offset = *until % 2 != 0;
        tree_node_count = *until + offset;
    } else {
        offset = s->data_node_count % 2 != 0;
        tree_node_count = s->data_node_count + offset;
    }
    if (tree_node_count == 0) {
        return SAQ_SUCCESS;
    }
    s->tree_nodes = malloc(sizeof(SAQ_merkle_node_t *) * tree_node_count);
    s->tree_node_count = 0;
    SAQ_list_t *l = s->data_nodes;
    SAQ_merkle_node_t *last = NULL;
    uint64_t nodes_added = 0;
    SAQ_merkle_node_t *n = NULL;
    if (SAQ_list_go_first(l) != SAQ_SUCCESS) {
        free(s->tree_nodes);
        s->tree_nodes = NULL;
        return SAQ_FAILURE;
    }
    while (SAQ_list_get_cur(l, (void **)&n) == SAQ_SUCCESS  && (until == NULL || nodes_added < *until)) {
        s->tree_nodes[nodes_added] = n;
        nodes_added++;
        last = n;
        if (SAQ_list_go_next(l) != SAQ_SUCCESS) {
            break;
        }
        n = NULL;
    }
    if (offset) {
        if (last == NULL) {
	    free(s->tree_nodes);
            s->tree_nodes = NULL;
            return SAQ_FAILURE;
        }
        s->tree_nodes[nodes_added] = last;
        nodes_added++;
    }
    s->tree_node_count = nodes_added;
    SAQ__merkle_stream_recursive_destroy(s->root);
    s->root = NULL;
    if (SAQ__merkle_stream_recursive_build(s, 0, s->tree_node_count, &(s->root))
        != SAQ_SUCCESS) {
        return SAQ_FAILURE;
    }
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_stream_finalize(SAQ_merkle_stream_t *s) {
    return SAQ_merkle_stream_finalize_until(s, NULL);
}

SAQ_STATUS
SAQ_merkle_stream_get_root_hash(SAQ_merkle_stream_t *s,
                                unsigned char *root_hash,
                                uint64_t *root_hash_len);

SAQ_STATUS
SAQ_merkle_stream_get_proof(SAQ_merkle_stream_t *s, uint64_t i,
                            SAQ_authentication_path_t **out) {
    if (s == NULL || out == NULL || *out != NULL || i > s->tree_node_count) {
        return SAQ_FAILURE;
    }

    if (i >= s->tree_node_count) {
        return SAQ_FAILURE;
    }
    SAQ_merkle_node_t **tree_nodes = s->tree_nodes;
    SAQ_merkle_node_t *cur_node = NULL;
    SAQ_merkle_node_t *parent = NULL;
    SAQ_merkle_node_t *left = NULL;
    SAQ_merkle_node_t *right = NULL;

    SAQ_authentication_path_t *proof = NULL;
    SAQ_authentication_node_t *an = NULL;

    uint64_t root_hash_len = 0;
    if (SAQ_merkle_stream_get_root_hash_len(s, &root_hash_len) != SAQ_SUCCESS) {
        return SAQ_FAILURE;
    }
    unsigned char *root_hash = malloc(root_hash_len);
    if (root_hash == NULL) {
        return SAQ_FAILURE;
    }
    if (SAQ_merkle_stream_get_root_hash(s, root_hash, &root_hash_len)
        != SAQ_SUCCESS) {
        free(root_hash);
        return SAQ_FAILURE;
    }

    cur_node = tree_nodes[i];
    if (SAQ_merkle_node_get_parent(cur_node, &parent) != SAQ_SUCCESS) {
        free(root_hash);
        return SAQ_FAILURE;
    }
    if (SAQ_authentication_path_init(&proof) != SAQ_SUCCESS) {
        free(root_hash);
        return SAQ_FAILURE;
    }
    while (parent != NULL) {
        SAQ_merkle_node_t *l = NULL;
        SAQ_merkle_node_t *r = NULL;
        left = NULL;
        right = NULL;
        if (SAQ_merkle_node_get_left(parent, &l) != SAQ_SUCCESS) {
            goto err;
        }
        if (SAQ_merkle_node_get_right(parent, &r) != SAQ_SUCCESS) {
            goto err;
        }
        if (cur_node == l) {
            if (r == NULL) {
                goto err;
            }
            right = r;
        } else {
            if (l == NULL) {
                goto err;
            }
            left = l;
        }
        if ((left != NULL && right != NULL)
            || (left == NULL && right == NULL)) {
            goto err;
        }
        uint64_t left_hash_len = 0;
        uint64_t right_hash_len = 0;
        unsigned char *left_hash = NULL;
        unsigned char *right_hash = NULL;
        SAQ_STATUS res = SAQ_SUCCESS;
        if (left != NULL) {
            SAQ_merkle_node_get_hash_len(left, &left_hash_len);
            left_hash = malloc(left_hash_len);
            if (left_hash == NULL) {
                goto err;
            }
            if (SAQ_merkle_node_get_hash(left, left_hash, &left_hash_len)
                != SAQ_SUCCESS) {
                res = SAQ_FAILURE;
                goto hash_cleanup;
            }
        } else if (right != NULL) {
            SAQ_merkle_node_get_hash_len(right, &right_hash_len);
            right_hash = malloc(right_hash_len);
            if (right_hash == NULL) {
                goto err;
            }
            if (SAQ_merkle_node_get_hash(right, right_hash, &right_hash_len)
                != SAQ_SUCCESS) {
                res = SAQ_FAILURE;
                goto hash_cleanup;
            }
        }
        unsigned char *sibling_hash;
        uint64_t sibling_hash_len;
        bool is_left;
        if (left_hash != NULL) {
            sibling_hash = left_hash;
            sibling_hash_len = left_hash_len;
            is_left = true;
        } else {
            sibling_hash = right_hash;
            sibling_hash_len = right_hash_len;
            is_left = false;
        }
        if (SAQ_authentication_node_new(s->hash_cb, sibling_hash,
                                        sibling_hash_len, is_left, &an)
            != SAQ_SUCCESS) {
            res = SAQ_FAILURE;
        }
    hash_cleanup:
        if (left_hash != NULL) {
            free(left_hash);
        }
        if (right_hash != NULL) {
            free(right_hash);
        }
        if (res != SAQ_SUCCESS) {
            goto err;
        }
        if (SAQ_authentication_path_append(proof, an) != SAQ_SUCCESS) {
            return SAQ_FAILURE;
        }
        cur_node = parent;
        if (SAQ_merkle_node_get_parent(cur_node, &parent) != SAQ_SUCCESS) {
            return SAQ_FAILURE;
        }
    }
    *out = proof;
    if (root_hash != NULL) {
        free(root_hash);
    }
    return SAQ_SUCCESS;
err:
    if (root_hash != NULL) {
        free(root_hash);
    }
    if (proof != NULL) {
        SAQ_authentication_path_destroy(&proof);
    }
    return SAQ_FAILURE;
}

SAQ_STATUS
SAQ_merkle_stream_get_root_hash_len(SAQ_merkle_stream_t *s,
                                    uint64_t *root_hash_len) {
    if (s == NULL || s->root == NULL || root_hash_len == NULL) {
        return SAQ_FAILURE;
    }
    return SAQ_merkle_node_get_hash_len(s->root, root_hash_len);
}

SAQ_STATUS
SAQ_merkle_stream_get_root_hash(SAQ_merkle_stream_t *s,
                                unsigned char *root_hash,
                                uint64_t *root_hash_len) {
    if (s == NULL || s->root == NULL || root_hash == NULL
        || root_hash_len == NULL) {
        return SAQ_FAILURE;
    }
    if (SAQ_merkle_node_get_hash(s->root, root_hash, root_hash_len)
        != SAQ_SUCCESS) {
        return SAQ_FAILURE;
    }
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_stream_byte_size(SAQ_merkle_stream_t *s, uint64_t *size) {
    if (s == NULL || size == NULL) {
	if (size != NULL) {
		*size = 0;
	}
        return SAQ_FAILURE;
    }
    SAQ_list_t *l = s->data_nodes;
    uint64_t sum = 0;
    if (SAQ_list_go_first(l) != SAQ_SUCCESS) {
        // This is an empty merkle tree, which is valid.
        // It therefore takes uint64_t + uint64_t to represent.
        if (size != NULL) {
            *size = sizeof(uint64_t) + sizeof(uint64_t) + 0;
        }
        return SAQ_SUCCESS;
    }
    SAQ_merkle_node_t *n = NULL;
    while (SAQ_list_get_cur(l, (void **)&n) == SAQ_SUCCESS) {
        uint64_t len = 0;
        if (SAQ_merkle_node_byte_size(n, &len) != SAQ_SUCCESS) {
            return SAQ_FAILURE;
        }
        sum += len;
        if (SAQ_list_go_next(l) != SAQ_SUCCESS) {
            break;
        }
        n = NULL;
    }
    *size = sizeof(uint64_t) + sizeof(uint64_t) + sum;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_stream_serialize(SAQ_merkle_stream_t *s, unsigned char *out,
                            uint64_t *out_len) {
    if (out == NULL || out_len == NULL) {
        if (out_len != NULL) {
            *out_len = 0;
        }
        return SAQ_FAILURE;
    }
    uint64_t len;
    if (SAQ_merkle_stream_byte_size(s, &len) != SAQ_SUCCESS) {
        *out_len = 0;
        return SAQ_FAILURE;
    }
    if (*out_len < len) {
        *out_len = 0;
        return SAQ_FAILURE;
    }
    *out_len = len;

    // tree_node_count || data_node_count || data_node(s)
    //
    // tree_node_count is used to denote where the merkle stream was
    // finalized to before serialization.
    uint64_t count = htonll(s->tree_node_count);
    memcpy(out, &count, sizeof(uint64_t));
    out += sizeof(uint64_t);
    len -= sizeof(uint64_t);

    count = htonll(s->data_node_count);
    memcpy(out, &count, sizeof(uint64_t));
    out += sizeof(uint64_t);
    len -= sizeof(uint64_t);

    SAQ_list_t *l = s->data_nodes;
    if (SAQ_list_go_first(l) != SAQ_SUCCESS) {
        return SAQ_SUCCESS;
    }
    SAQ_merkle_node_t *n = NULL;
    while (SAQ_list_get_cur(l, (void **)&n) == SAQ_SUCCESS) {
        uint64_t ol = len;
        if (SAQ_merkle_node_serialize(n, out, &ol) != SAQ_SUCCESS) {
            *out_len = 0;
            return SAQ_FAILURE;
        }
        out += ol;
        len -= ol;
        if (SAQ_list_go_next(l) != SAQ_SUCCESS) {
            break;
        }
        n = NULL;
    }
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_stream_deserialize(unsigned char *in, uint64_t in_len,
                              SAQ_hash_cb_ptr hash_cb,
                              SAQ_merkle_stream_t **out) {
    if (in == NULL || in_len < sizeof(uint64_t) + sizeof(uint64_t)) {
        return SAQ_FAILURE;
    }
    // tree_node_len || data_node_len || data_node(s)
    //
    // tree_node_len is used to denote where the merkle stream was
    // finalized to before serialization.
    uint64_t tree_node_count = ntohll(*(uint64_t *)in);
    in += sizeof(uint64_t);
    in_len -= sizeof(uint64_t);

    uint64_t data_node_count = ntohll(*(uint64_t *)in);
    in += sizeof(uint64_t);
    in_len -= sizeof(uint64_t);
    SAQ_merkle_stream_t *ms = NULL;
    if (SAQ_merkle_stream_new(hash_cb, &ms) != SAQ_SUCCESS) {
        return SAQ_FAILURE;
    }

    for (uint64_t i = 0; i < data_node_count; i++) {
        SAQ_merkle_node_t *n = NULL;
        uint64_t byte_size;
        if (SAQ_merkle_node_deserialize(in, in_len, hash_cb, &n)
            != SAQ_SUCCESS) {
            SAQ_merkle_stream_destroy(&ms);
            return SAQ_FAILURE;
        }
        if (SAQ_merkle_node_byte_size(n, &byte_size) != SAQ_SUCCESS) {
            SAQ_merkle_stream_destroy(&ms);
            return SAQ_FAILURE;
        }
        in += byte_size;
        in_len -= byte_size;
        if (SAQ_list_append(ms->data_nodes, n) != SAQ_SUCCESS) {
            SAQ_merkle_stream_destroy(&ms);
            return SAQ_FAILURE;
        }
    }
    ms->data_node_count = data_node_count;
    if (SAQ_merkle_stream_finalize_until(ms, &tree_node_count) != SAQ_SUCCESS) {
        SAQ_merkle_stream_destroy(&ms);
        return SAQ_FAILURE;
    }
    *out = ms;
    return SAQ_SUCCESS;
}

SAQ_STATUS
SAQ_merkle_stream_max_authentication_path_byte_size(SAQ_merkle_stream_t *ms, uint64_t *size) {
    uint64_t root_hash_len;
    uint64_t max_ap_len;
    if (ms == NULL || size == NULL) {
        return SAQ_FAILURE;
    }

    if (SAQ_merkle_stream_get_root_hash_len(ms, &root_hash_len) != SAQ_SUCCESS) {
        return SAQ_FAILURE;
    }

    max_ap_len = ceil(log2((double)ms->tree_node_count));
    *size = sizeof(uint32_t) + max_ap_len * (sizeof(uint8_t) + sizeof(uint64_t) + root_hash_len);

    return SAQ_SUCCESS;
}
