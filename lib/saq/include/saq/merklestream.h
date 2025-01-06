#ifndef __MERKLE_STREAM_H__
#define __MERKLE_STREAM_H__

#include "merkleauthpath.h"
#include "merklecommon.h"
#include "merklenode.h"

/// \brief A Merkle tree based stream.
typedef struct SAQ_merkle_stream SAQ_merkle_stream_t;

struct SAQ_merkle_stream {
    SAQ_merkle_node_t *root;
    SAQ_hash_cb_ptr hash_cb;
    SAQ_list_t *data_nodes;
    uint64_t data_node_count;
    SAQ_merkle_node_t **tree_nodes;
    uint64_t tree_node_count;
};

/// \brief Constructs a new SAQ_merkle_stream_t.
///
/// \param[in] hash_cb The callback to use for hashing.
/// \param[out] out Points to the created SAQ_merkle_stream_t. *out must be NULL.
///
/// \return SAQ_SUCCESS if out was successfully created; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_stream_new(SAQ_hash_cb_ptr hash_cb, SAQ_merkle_stream_t **out);

/// \brief Destroys SAQ_merkle_stream_t.
///
/// \param[in,out] in Points the SAQ_merkle_node_t * to be freed. *in will be set to NULL
///                on return.
///
/// \return SAQ_SUCCESS if ap was successfully destroyed; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_stream_destroy(SAQ_merkle_stream_t **in);

/// \brief Adds data to the merkle stream.
///
/// \param[in] s The Merkle tree based stream to add the data to.
/// \param[in] data The data to be added to s.
/// \param[in] data_len The length of data.
///
/// \return SAQ_SUCCESS if data was successfully added to s; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_stream_write(SAQ_merkle_stream_t *s, unsigned char *data,
                        uint64_t data_len);

/// \brief Finalizes and rebuilds the underlying Merkle tree.
///
/// \param[in] s The Merkle tree based stream to be finalized.
///
/// \return SAQ_SUCCESS if s was succesfully finalized; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_stream_finalize(SAQ_merkle_stream_t *s);

/// \brief Fetches the authentication path of the i'th block of data in the Merkle tree.
///
/// \param[in] s The Merkle tree based stream.
/// \param[in] i The index of the block of data to start the authentication path from.
/// \param[out] out The authentication path associated with the i'th block of data. *out must be NULL.
///
/// \return SAQ_SUCCESS if an authentication path was successfully created; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_stream_get_proof(SAQ_merkle_stream_t *s, uint64_t i,
                            SAQ_authentication_path_t **out);

/// \brief Fetches the length of a Merkle tree based stream's root hash.
///
/// \param[in] s The Merkle tree based stream.
/// \param[out] root_hash_len Contains the hash length.
///
/// \return SAQ_SUCCESS if the hash length was succesfully fetched; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_stream_get_root_hash_len(SAQ_merkle_stream_t *s,
                                    uint64_t *root_hash_len);

/// \brief Fetches a Merkle tree based stream's root hash.
///
/// \param[in] s The Merkle tree based stream.
/// \param[in,out] root_hash The memory region to copy the hash into.
/// \param[in,out] root_hash_len Contains the length of the hash byte region. *root_hash_len contains the hash length on return.
///
/// \return SAQ_SUCCESS if the hash was succesfully fetched; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_stream_get_root_hash(SAQ_merkle_stream_t *s,
                                unsigned char *root_hash,
                                uint64_t *root_hash_len);

/// \brief Returns the number of bytes required to serialize a given Merkle tree based stream.
///
/// \param[in] s The SAQ_merkle_stream_t to compute the byte size of.
/// \param[out] size The computed size of size. On error *size is set to 0.
///
/// \return SAQ_SUCCESS if the byte size of size was computed; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_stream_byte_size(SAQ_merkle_stream_t *s, uint64_t *size);

/// \brief Serializes a given Merkle tree based stream and stores bytes in given byte region.
///
/// \param[in] s The Merkle tree based stream to be serialized.
/// \param[in,out] out The byte region to copy the serialized form of n into.
/// \param[in,out] out_len The length of out. On return *out_len is set to the number of bytes
/// 			used to serialize n.
///
/// \return SAQ_SUCCESS if s was succesfully serialized; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_stream_serialize(SAQ_merkle_stream_t *s, unsigned char *out,
                            uint64_t *out_len);

/// \brief Derializes a given serialized Merkle tree based stream.
///
/// \param[in] in The byte region containing the serialized Merkle tree based stream.
/// \param[in] in_len The length of the byte region in.
/// \param[in] hash_cb The callback to use for hashing.
/// \param[out] out The deserialized SAQ_authentication_node_t. *out must be NULL.
///
/// \return SAQ_SUCCESS if in was succesfully deserialized; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_merkle_stream_deserialize(unsigned char *in, uint64_t in_len,
                              SAQ_hash_cb_ptr hash_cb,
                              SAQ_merkle_stream_t **out);

/// \brief Returns the maximum number of bytes an authenticating path can be.
///
/// \param[in] ms The merkle stream.
/// \param[out] size The maximum number of bytes an authenticating path can be.
///
/// \return SAQ_SUCCESS if in was succesfully deserialized; SAQ_FAILURE otherwise.

SAQ_STATUS
SAQ_merkle_stream_max_authentication_path_byte_size(SAQ_merkle_stream_t *ms, uint64_t *size);

#endif /* __MERKLE_STREAM_H__ */
