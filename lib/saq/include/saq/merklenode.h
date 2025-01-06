#ifndef __MERKLE_NODE_H__
#define __MERKLE_NODE_H__

#include <stdint.h>
#include "merklecommon.h"

/// \brief A merkle tree node.
typedef struct SAQ_merkle_node SAQ_merkle_node_t;

struct SAQ_merkle_node {
    struct SAQ_merkle_node *left;
    struct SAQ_merkle_node *right;
    struct SAQ_merkle_node *parent;
    unsigned char *hash;
    uint64_t hash_len;
    SAQ_hash_cb_ptr hash_cb;
};

/// \brief Constructs a new SAQ_merkle_node_t.
///
/// \param[in] hash_cb The callback to use for hashing.
/// \param[in] left The left child of the merkle node being created.
/// 		If right is NULL, left must be NULL.
/// 		If right is not NULL, left must be not NULL.
/// \param[in] right The right child of the merkle node being created.
/// 		If left is NULL, right must be NULL.
/// 		If left is not NULL, right must be not NULL.
/// \param[in] data The data to be hashed. If Data is not NULL, left and right must be NULL.
/// \param[in] data_len The length of data.
/// \param[out] out Points to the created SAQ_merkle_node_t. *out must be NULL.
///
/// \return SAQ_SUCCESS if out was successfully created; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_node_new(SAQ_hash_cb_ptr hash_cb, SAQ_merkle_node_t *left,
                    SAQ_merkle_node_t *right, unsigned char *data,
                    uint64_t data_len, SAQ_merkle_node_t **out);

/// \brief Fetches the length of a merkle node's hash.
///
/// \param[in] node The node containing the desired hash length.
/// \param[out] hash_len Contains the hash length.
///
/// \return SAQ_SUCCESS if the hash length was succesfully fetched; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_node_get_hash_len(SAQ_merkle_node_t *node, uint64_t *hash_len);

/// \brief Fetches a merkle node's hash.
///
/// \param[in] node The node containing the desired hash.
/// \param[in,out] hash The memory region to copy the hash into.
/// \param[in,out] hash_len Contains the length of the hash byte region. *hash_len contains the hash length on return.
///
/// \return SAQ_SUCCESS if the hash was succesfully fetched; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_node_get_hash(SAQ_merkle_node_t *node, unsigned char *hash,
                         uint64_t *hash_len);

/// \brief Fetches a merkle node's left child.
///
/// \param[in] node The target node.
/// \param[in,out] out Points to the left child of node. *out must be NULL.
///
/// \return SAQ_SUCCESS if the left child was succesfully fetched; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_node_get_left(SAQ_merkle_node_t *node, SAQ_merkle_node_t **out);

/// \brief Fetches a merkle node's right child.
///
/// \param[in] node The target node.
/// \param[in,out] out Points to the right child of node. *out must be NULL.
///
/// \return SAQ_SUCCESS if the right child was succesfully fetched; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_node_get_right(SAQ_merkle_node_t *node, SAQ_merkle_node_t **out);

/// \brief Sets a merkle node's parent.
///
/// \param[in] node The target node.
/// \param[in,out] parent The desired parent of node.
///
/// \return SAQ_SUCCESS if the parent was succesfully set; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_node_set_parent(SAQ_merkle_node_t *node, SAQ_merkle_node_t *parent);

/// \brief Fetches a merkle node's parent.
///
/// \param[in] node The target node.
/// \param[in,out] out Points to the parent of node. *out must be NULL.
///
/// \return SAQ_SUCCESS if the parent was succesfully fetched; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_node_get_parent(SAQ_merkle_node_t *node, SAQ_merkle_node_t **out);

/// \brief Copies a merkle node.
///
/// \param[in] in The source node.
/// \param[out] out The destination node. *out must be NULL.
///
/// \return SAQ_SUCCESS if in was successfully copied; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_node_copy(SAQ_merkle_node_t *in, SAQ_merkle_node_t **out);

/// \brief Destroys a given merkle node.
///
/// \param[in] node The node to be destroyed.
///
/// \return SAQ_SUCCESS if in was successfully destroyed; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_node_destroy(SAQ_merkle_node_t *node);

/// \brief Returns the number of bytes required to serialize a given SAQ_merkle_node_t.
///
/// \param[in] n The SAQ_merkle_node_t to compute the byte size of.
/// \param[out] size The computed size of n. On error *size is set to 0.
///
/// \return SAQ_SUCCESS if the byte size of n was computed; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_node_byte_size(SAQ_merkle_node_t *n, uint64_t *size);

/// \brief Serializes a given SAQ_merkle_node_t and stores bytes in given byte region.
///
/// \param[in] n The SAQ_merkle_node_t to be serialized.
/// \param[in,out] out The byte region to copy the serialized form of n into.
/// \param[in,out] out_len The length of out. On return *out_len is set to the number of bytes
/// 			used to serialize n.
///
/// \return SAQ_SUCCESS if n was succesfully serialized; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_node_serialize(SAQ_merkle_node_t *n, unsigned char *out,
                          uint64_t *out_len);

/// \brief Derializes a given serialized SAQ_merkle_node_t.
///
/// \param[in] in The byte region containing the serialized SAQ_merkle_node_t.
/// \param[in] in_len The length of the byte region in.
/// \param[in] hash_cb The callback to use for hashing.
/// \param[out] out The deserialized SAQ_merkle_node_t. *out must be NULL.
///
/// \return SAQ_SUCCESS if in was succesfully deserialized; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_node_deserialize(unsigned char *in, uint64_t in_len,
                            SAQ_hash_cb_ptr hash_cb, SAQ_merkle_node_t **out);

#endif /* __MERKLE_NODE_H__ */
