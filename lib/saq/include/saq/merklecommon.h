#ifndef __MERKLE_COMMON_H__
#define __MERKLE_COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define SAQ_STATUS  int

#define SAQ_SUCCESS 0
#define SAQ_FAILURE 1

#ifndef htonll
#if __BIG_ENDIAN__
# define htonll(x) (x)
#else
# define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif
#endif

#ifndef ntohll
#if __BIG_ENDIAN__
# define ntohll(x) (x)
#else
# define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif
#endif

/// \brief Hashing callback function used by a Merkle Nodes, Authenticating Paths, and Merkle Streams.
///
/// \param[in] data The data to be hashed.
/// \param[in] data_len The length of the byte region pointed to by data.
/// \param[out] hash The byte region to store the computed hash in.
/// \param[out] hash_len The length of the computed hash. If hash is NULL
///             hash_len will be updated with how large the hash would have been.
///
/// \return SAQ_SUCCESS if hashing was successful; SAQ_FAILURE otherwise.
typedef SAQ_STATUS(SAQ_hash_cb)(unsigned char *data, uint64_t data_len,
                                unsigned char *hash, uint64_t *hash_len);
typedef SAQ_hash_cb *SAQ_hash_cb_ptr;

/// \brief A list.
typedef struct SAQ_list SAQ_list_t;

/// \brief A list node.
typedef struct SAQ_list_node SAQ_list_node_t;

/// \brief A generic list node.
struct SAQ_list {
    SAQ_list_node_t *head;
    SAQ_list_node_t *tail;
    SAQ_list_node_t *cur;
};

struct SAQ_list_node {
    void *data;
    struct SAQ_list_node *next;
};

/// \brief Initalizes an SAQ_list_t.
///
/// \param[in, out] l The list to be initalized.

/// \return SAQ_SUCCESS if the list is initalized successfully; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_list_init(SAQ_list_t **l);

/// \brief Moves the list's iterator to the first element of the list.
///
/// \param[in] l The list.
///
/// \return SAQ_SUCCESS if iterator successfully moved;
///         SAQ_FAILURE if the list is not initialized or is empty.
SAQ_STATUS
SAQ_list_go_first(SAQ_list_t *n);

/// \brief Moves the list's iterator to the next element.
///
/// \param[in] l The list.
///
/// \return SAQ_SUCCESS if iterator successfully moved; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_list_go_next(SAQ_list_t *n);

/// \brief Gets the data that the internal iterator is currently pointing at.
///
/// \param[in] l The list.
/// \param[out] out The data from the current position in the list.
///
/// \return A pointer to the data if found; NULL otherwise.
SAQ_STATUS
SAQ_list_get_cur(SAQ_list_t *n, void **out);

/// \brief Appends data to a SAQ_list_t.
///
/// \param[in] l The list to append the data, d, to.
/// \param[in] d The data to append to list l.
///
/// \return SAQ_SUCCESS if d was appended to l; SAQ_FAILURE otherwise.
SAQ_STATUS
SAQ_list_append(SAQ_list_t *l, void *d);

/// \brief Destroys the given SAQ_list_t l and optionally frees the data it points to.
///
/// \param[in] l The list to be destroyed.
/// \param[in] free_cb The function to use to free the data the list points to.
///                    If NULL then the data is not freed.
void
SAQ_list_destroy(SAQ_list_t **l, void (*free_cb)(void *));

#endif /* __MERKLE_COMMON_H__ */
