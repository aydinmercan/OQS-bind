#ifndef __MERKLE_AUTH_PATH_H__
#define __MERKLE_AUTH_PATH_H__

#include <stdbool.h>

#include "merklecommon.h"

/// \brief An authentication path.
typedef SAQ_list_t SAQ_authentication_path_t;

/// \brief Initalizes an SAQ_authentication_path_t.
///
/// \param[in, out] ap The authentication path to be initalized.
#define SAQ_authentication_path_init     SAQ_list_init

/// \brief Moves the authentication path's iterator to the first
///        element of the list.
///
/// \param[in] ap The authentication path.
///
/// \return SAQ_SUCCESS if iterator successfully moved;
///         SAQ_FAILURE if the list is not initialized or is empty.
#define SAQ_authentication_path_go_first SAQ_list_go_first

/// \brief Moves the authentication path's iterator to the next element.
///
/// \param[in] ap The authentication path.
///
/// \return SAQ_SUCCESS if iterator successfully moved; SAQ_FAILURE otherwise.
#define SAQ_authentication_path_go_next SAQ_list_go_next

/// \brief Gets the next node in the authentication path.
///
/// \param[in] ap The authentication path.
/// \param[out] p The data that the internal iterator is pointing at.
///
/// \return SAQ_SUCCESS if next node was successfully fetched; SAQ_FAILURE otherwise.
#define SAQ_authentication_path_get_cur SAQ_list_get_cur

/// \brief Appends an authentication node to a given authentication path.
///
/// \param[in] ap The authentication path to append the authentication node, an, to.
/// \param[in] an The authentication node to append to authentication path ap.
///
/// \return SAQ_SUCCESS if an was appended to ap; SAQ_FAILURE otherwise.
#define SAQ_authentication_path_append   SAQ_list_append

/// \brief An authentication node.
typedef struct SAQ_authentication_node SAQ_authentication_node_t;

/// \brief A node of an authentication path.
struct SAQ_authentication_node {
    unsigned char *sibling_hash;
    uint64_t sibling_hash_len;
    bool is_left;
    SAQ_hash_cb_ptr hash_cb;
};

/// \brief Constructs a new SAQ_authentication_node_t.
///
/// \param[in] hash_cb The callback to use for hashing.
/// \param[in] sibling_hash The hash of the sibling sub-Merkle tree.
/// \param[in] sibling_hash_len The length of sibling_hash.
/// \param[in] sibling_is_left Indicates if the sibling is a left sub-Merkle tree or a right sub-Merkle tree.
/// \param[out] out Points to the created SAQ_authentication_node_t. *out must be NULL.
///
/// \return SAQ_SUCCESS if out was successfully created; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_authentication_node_new(SAQ_hash_cb_ptr hash_cb,
                            unsigned char *sibling_hash,
                            uint64_t sibling_hash_len, bool sibling_is_left,
                            SAQ_authentication_node_t **out);

/// \brief Fetches the current SAQ_authentication_node_t from a given SAQ_authentication_path_t.
///
/// \param[in] ap The authentication path.
/// \param[out] out The fretched SAQ_authentication_node_t.
///
/// \return SAQ_SUCCESS if fetching the SAQ_authentication_node_t was successful; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_authentication_path_get_node(SAQ_authentication_path_t *ap,
                                 SAQ_authentication_node_t **out);

/// \brief Destroys a given SAQ_authentication_path_t.
///
/// \param[in,out] ap Points the SAQ_authentication_path_t * to be freed. *ap will be set to NULL
///                on return.
///
/// \return SAQ_SUCCESS if ap was successfully destroyed; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_authentication_path_destroy(SAQ_authentication_path_t **ap);

/// \brief Proves whether or not a data region belongs to a given Merkle tree authentication path, ap.
///
/// \param[in] data The data to be verified.
/// \param[in] data_len The length of the data.
/// \param[in] root_hash The root hash of the merkle tree that owns the authentication path ap.
/// \param[in] root_hash_len The length of the root hash.
/// \param[in] ap The authentication path to be used as part of this proof.
///
/// \return SAQ_SUCCESS if data is valid given root_hash and ap; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_authentication_path_prove(unsigned char *data, uint64_t data_len,
                              unsigned char *root_hash, uint64_t root_hash_len,
                              SAQ_authentication_path_t *ap);

/// \brief Destroys a given SAQ_authentication_node_t.
///
/// \param[in] node The SAQ_authentication_node_t to be destroyed.
///
/// \return SAQ_SUCCESS if node was destroyed; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_authentication_node_destroy(SAQ_authentication_node_t *node);

/// \brief Returns the number of bytes required to serialize a given SAQ_authentication_node_t.
///
/// \param[in] n The SAQ_authentication_node_t to compute the byte size of.
/// \param[out] size The computed size of n. On error *size is set to 0.
///
/// \return SAQ_SUCCESS if the byte size of n was computed; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_authentication_node_byte_size(SAQ_authentication_node_t *n, uint64_t *size);

/// \brief Serializes a given SAQ_authentication_node_t and stores bytes in given byte region.
///
/// \param[in] n The SAQ_authentication_node_t to be serialized.
/// \param[in,out] out The byte region to copy the serialized form of n into.
/// \param[in,out] out_len The length of out. On return *out_len is set to the number of bytes
/// 			used to serialize n.
///
/// \return SAQ_SUCCESS if n was succesfully serialized; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_authentication_node_serialize(SAQ_authentication_node_t *n,
                                  unsigned char *out, uint64_t *out_len);

/// \brief Derializes a given serialized SAQ_authentication_node_t.
///
/// \param[in] in The byte region containing the serialized SAQ_authentication_node_t.
/// \param[in] in_len The length of the byte region in.
/// \param[in] hash_cb The callback to use for hashing.
/// \param[out] n The deserialized SAQ_authentication_node_t. *n must be NULL.
///
/// \return SAQ_SUCCESS if in was succesfully deserialized; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_authentication_node_deserialize(unsigned char *in, uint64_t in_len,
                                    SAQ_hash_cb_ptr hash_cb,
                                    SAQ_authentication_node_t **out);

/// \brief Returns the number of bytes required to serialize a given SAQ_authentication_path_t.
///
/// \param[in] ap The SAQ_authentication_path_t to compute the byte size of.
/// \param[out] size The computed size of ap. On error *size is set to 0.
///
/// \return SAQ_SUCCESS if the byte size of ap was computed; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_authentication_path_byte_size(SAQ_authentication_path_t *ap,
                                  uint64_t *size);

/// \brief Serializes a given SAQ_authentication_path_t and stores bytes in given byte region.
///
/// \param[in] ap The SAQ_authentication_path_t to be serialized.
/// \param[in,out] out The byte region to copy the serialized form of ap into.
/// \param[in,out] out_len The length of out. On return *out_len is set to the number of bytes
/// 			used to serialize n.
///
/// \return SAQ_SUCCESS if ap was succesfully serialized; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_authentication_path_serialize(SAQ_authentication_path_t *ap,
                                  unsigned char *out, uint64_t *out_len);

/// \brief Derializes a given serialized SAQ_authentication_path_t.
///
/// \param[in] in The byte region containing the serialized SAQ_authentication_path_t.
/// \param[in] in_len The length of the byte region in.
/// \param[in] hash_cb The callback to use for hashing.
/// \param[out] ap The deserialized SAQ_authentication_path_t. *n must be NULL.
///
/// \return SAQ_SUCCESS if in was succesfully deserialized; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_authentication_path_deserialize(unsigned char *in, uint64_t in_len,
                                    SAQ_hash_cb_ptr hash_cb,
                                    SAQ_authentication_path_t **out);

#endif /* __MERKLE_AUTH_PATH_H__ */
