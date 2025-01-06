/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <libgen.h>
#include <saq/merklestream.h>
#include <stdbool.h>
#include <openssl/evp.h>

#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include <dst/xmss.h>

#include "dst_internal.h"
#include "dst_openssl.h"
#include "dst_parse.h"

#define DST_RET(a)        \
	{                 \
		ret = a;  \
		goto err; \
	}

#define SAQ_SHA256_DIGESTLENGTH 16
static SAQ_STATUS
merkle_ossl_sha256_cb(unsigned char *data, uint64_t data_len, unsigned char *hash,
          uint64_t *hash_len) {
    unsigned char tmphash[SAQ_SHA256_DIGESTLENGTH * 2];
    unsigned int tmphash_len = SAQ_SHA256_DIGESTLENGTH * 2;
    if (hash == NULL) {
        // set what the length would have been and return failure;
        *hash_len = SAQ_SHA256_DIGESTLENGTH;
        return SAQ_FAILURE;
    }
    SAQ_STATUS ret = SAQ_FAILURE;
    if (*hash_len < SAQ_SHA256_DIGESTLENGTH) {
        return SAQ_FAILURE;
    }

    EVP_MD_CTX *mdctx = NULL;
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        goto finish;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        goto finish;
    }

    if (EVP_DigestUpdate(mdctx, data, data_len) != 1) {
        goto finish;
    }

    if (EVP_DigestFinal(mdctx, tmphash, &tmphash_len) != 1) {
        goto finish;
    }
    memcpy(hash, tmphash, SAQ_SHA256_DIGESTLENGTH);
    *hash_len = SAQ_SHA256_DIGESTLENGTH;
    ret = SAQ_SUCCESS;

finish:
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }
    return (ret);
}

typedef struct merkle_tags {
	unsigned int ntags, merkle_tree_tag;
} merkle_tags_t;

typedef struct saq_merkle_alginfo {
	uint64_t root_hash_size;
	merkle_tags_t tags;
} saq_merkle_alginfo_t;

static const saq_merkle_alginfo_t *
saqmerkle_alg_info(dst_algorithm_t key_alg) {
	if (key_alg == DST_ALG_MERKLE_TREE) {
		static const saq_merkle_alginfo_t merkle_alginfo = {
			.root_hash_size = SAQ_SHA256_DIGESTLENGTH,
			.tags = {
				.ntags = MERKLE_TREE_NTAGS,
				.merkle_tree_tag = TAG_MERKLE_TREE,
			},
		};
		return &merkle_alginfo;
	}
	return NULL;
}

struct merkle_meta {
	dst_key_t *key;
	char *dir;
};

static void
merkle_meta_set_dir(merkle_meta_t *s, const dst_key_t *key, const char *directory) {
	if (s->dir != NULL) {
		isc_mem_free(key->mctx, s->dir);
	}
	if (directory != NULL) {
		s->dir = isc_mem_strdup(key->mctx, directory); 
	} else {
		s->dir = NULL;
	}
}

static bool
merkle_meta_dir_is_set(merkle_meta_t *s) {
	return s->dir != NULL;
}

static void
merkle_meta_init(merkle_meta_t **s, dst_key_t *key, char *directory) {
	if (s == NULL) {
		return;
	}
	merkle_meta_t *sm = isc_mem_get(key->mctx, sizeof(merkle_meta_t));
	sm->key = key;
	if (directory != NULL) {
		sm->dir = isc_mem_strdup(key->mctx, directory); 
	} else {
		sm->dir = NULL;
	}
	*s = sm;
}

static void
merkle_meta_destroy(merkle_meta_t **s) {
	if (s == NULL) {
		return;
	}
	merkle_meta_t *sm = *s;
	dst_key_t *key = sm->key;
	if (key != NULL) {
		if (sm->dir != NULL) {
			isc_mem_free(key->mctx, sm->dir);
			sm->dir = NULL;
		}
		isc_mem_put(key->mctx, sm, sizeof(merkle_meta_t));
	}
	*s = NULL;
}

static isc_result_t
keys_to_file(const dst_key_t *key, unsigned char *tree_buf, size_t tree_len,
	     const char *directory) {
	const saq_merkle_alginfo_t *alginfo =
		saqmerkle_alg_info(key->key_alg);
	REQUIRE(alginfo != NULL);
	dst_private_t priv;
	priv.elements[0].tag = alginfo->tags.merkle_tree_tag;
	priv.elements[0].length = tree_len;
	priv.elements[0].data = tree_buf;

	priv.nelements = 1;
	return dst__privstruct_writefile(key, &priv, directory);
}

static isc_result_t
save_merkle_tree(SAQ_merkle_stream_t *tree, merkle_meta_t *meta) {
	uint64_t treelen = 0;
	uint64_t buflen = 0;
	unsigned char *treebuf = NULL;
	if (SAQ_merkle_stream_byte_size(tree, &treelen)
			!= SAQ_SUCCESS) {
		return (ISC_R_NOMEMORY);
	}
	treebuf = isc_mem_get(meta->key->mctx, treelen);
	if (treebuf == NULL) {
		return (ISC_R_NOMEMORY);
	}
	buflen = treelen;
	if(SAQ_merkle_stream_serialize(tree, treebuf, &treelen)
			!= SAQ_SUCCESS) {
		isc_mem_put(meta->key->mctx, treebuf, buflen);
		return (ISC_R_NOMEMORY);
	}
	if (keys_to_file(meta->key, treebuf, treelen, meta->dir) !=
	    ISC_R_SUCCESS)
	{
		isc_mem_put(meta->key->mctx, treebuf, buflen);
		return (ISC_R_NOMEMORY);
	}
	isc_mem_put(meta->key->mctx, treebuf, buflen);
	return (ISC_R_SUCCESS);
}

static isc_result_t
saqmerkle_createctx(dst_key_t *key, dst_context_t *dctx) {
	isc_buffer_t *buf = NULL;
	const saq_merkle_alginfo_t *alginfo =
		saqmerkle_alg_info(dctx->key->key_alg);

	UNUSED(key);

	REQUIRE(alginfo != NULL);

	isc_buffer_allocate(dctx->mctx, &buf, 64);
	dctx->ctxdata.generic = buf;

	return (ISC_R_SUCCESS);
}

static void
saqmerkle_destroyctx(dst_context_t *dctx) {
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	const saq_merkle_alginfo_t *alginfo =
		saqmerkle_alg_info(dctx->key->key_alg);

	REQUIRE(alginfo != NULL);

	if (buf != NULL) {
		isc_buffer_free(&buf);
	}
	dctx->ctxdata.generic = NULL;
}

static isc_result_t
saqmerkle_adddata(dst_context_t *dctx, const isc_region_t *data) {
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	isc_buffer_t *nbuf = NULL;
	isc_region_t r;
	unsigned int length;
	isc_result_t result;
	const saq_merkle_alginfo_t *alginfo =
		saqmerkle_alg_info(dctx->key->key_alg);

	REQUIRE(alginfo != NULL);

	result = isc_buffer_copyregion(buf, data);
	if (result == ISC_R_SUCCESS) {
		return (ISC_R_SUCCESS);
	}

	length = isc_buffer_length(buf) + data->length + 64;
	isc_buffer_allocate(dctx->mctx, &nbuf, length);
	isc_buffer_usedregion(buf, &r);
	(void)isc_buffer_copyregion(nbuf, &r);
	(void)isc_buffer_copyregion(nbuf, data);
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = nbuf;

	return (ISC_R_SUCCESS);
}

static isc_result_t
saqmerkle_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	// We are treating "sign" close to an "add" function. The actual
	// signature will be generated when "finalizesignature" is called.
	isc_result_t ret;
	dst_key_t *key = dctx->key;
	isc_region_t tbsreg;
	isc_region_t sigreg;
	SAQ_merkle_stream_t *tree = key->keydata.saq_merkle_tree.tree;
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	uint64_t sig_index = tree->data_node_count;
	const saq_merkle_alginfo_t *alginfo =
		saqmerkle_alg_info(key->key_alg);

	REQUIRE(alginfo != NULL);
	isc_buffer_availableregion(sig, &sigreg);
	if (sigreg.length < sizeof(uint64_t)) {
		DST_RET(ISC_R_NOSPACE);
	}
	INSIST(sigreg.length == sizeof(uint64_t));
	isc_buffer_usedregion(buf, &tbsreg);
	isc_mutex_lock(&(key->keydata.saq_merkle_tree.lock));
	if (SAQ_merkle_stream_write(tree, tbsreg.base, tbsreg.length)
			!= SAQ_SUCCESS)
	{
		isc_mutex_unlock(&(key->keydata.saq_merkle_tree.lock));
		DST_RET(dst__openssl_toresult3(dctx->category,
					       "SAQ_merkle_stream_write",
					       DST_R_SIGNFAILURE));
	}
	isc_mutex_unlock(&(key->keydata.saq_merkle_tree.lock));
	isc_buffer_putmem(sig, (const unsigned char *)&sig_index, sizeof(uint64_t));
	ret = ISC_R_SUCCESS;

err:
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return (ret);
}

static isc_result_t
saqmerkle_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_result_t ret;
	dst_key_t *key = dctx->key;
	isc_region_t tbsreg, rhreg;
	isc_buffer_t *root_hash = key->keydata.saq_merkle_tree.root_hash;
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	SAQ_authentication_path_t *ap = NULL;
	const saq_merkle_alginfo_t *alginfo =
		saqmerkle_alg_info(key->key_alg);
	REQUIRE(alginfo != NULL);

	if (root_hash == NULL) {
		DST_RET(DST_R_VERIFYFAILURE);
	}

	isc_buffer_usedregion(buf, &tbsreg);
	isc_buffer_usedregion(root_hash, &rhreg);
	if (SAQ_authentication_path_deserialize(sig->base, sig->length,
				merkle_ossl_sha256_cb, &ap) != SAQ_SUCCESS)
	{
		DST_RET(DST_R_VERIFYFAILURE);
	}

	INSIST(rhreg.length == SAQ_SHA256_DIGESTLENGTH);
	if (SAQ_authentication_path_prove(tbsreg.base, tbsreg.length,
						rhreg.base, rhreg.length, ap)
			!= SAQ_SUCCESS)
	{
		DST_RET(DST_R_VERIFYFAILURE);
	}
	ret = ISC_R_SUCCESS;
err:
	if (ap != NULL) {
		SAQ_authentication_path_destroy(&ap);
	}
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return (ret);
}

static isc_result_t
saqmerkle_generate(dst_key_t *key, int param, void (*callback)(int)) {
	isc_result_t ret;
	SAQ_merkle_stream_t *tree = NULL;
	const saq_merkle_alginfo_t *alginfo =
		saqmerkle_alg_info(key->key_alg);
	UNUSED(callback);
	UNUSED(param);

	REQUIRE(alginfo != NULL);

	if (SAQ_merkle_stream_new(merkle_ossl_sha256_cb, &tree) != SAQ_SUCCESS) 
	{
		DST_RET(DST_R_CRYPTOFAILURE);
	}

	key->key_size = alginfo->root_hash_size * 8;
	key->keydata.saq_merkle_tree.tree = tree;
	key->keydata.saq_merkle_tree.root_hash = NULL;
	isc_mutex_init(&(key->keydata.saq_merkle_tree.lock));
	merkle_meta_init(&(key->keydata.saq_merkle_tree.meta), key, NULL);
	ret = ISC_R_SUCCESS;

	return (ret);

err:
	if (tree != NULL) {
		SAQ_merkle_stream_destroy(&tree);
	}

	return (ret);
}

static isc_result_t
saqmerkle_finalizekey(dst_key_t *key) {
	uint64_t root_hash_len = 0;
	isc_buffer_t *root_hash = NULL;
	isc_region_t rhr;
	SAQ_merkle_stream_t *tree = key->keydata.saq_merkle_tree.tree;
	const saq_merkle_alginfo_t *alginfo =
		saqmerkle_alg_info(key->key_alg);
	
	REQUIRE(alginfo != NULL);

	if (SAQ_merkle_stream_finalize(tree)
			!= SAQ_SUCCESS) {
		return (DST_R_CRYPTOFAILURE);
	}
	if (SAQ_merkle_stream_get_root_hash_len(tree, &root_hash_len) == SAQ_SUCCESS) {
		isc_buffer_allocate(key->mctx, &root_hash, root_hash_len);
		isc_buffer_availableregion(root_hash, &rhr);
		INSIST(rhr.length >= root_hash_len);
		if (SAQ_merkle_stream_get_root_hash(tree, rhr.base, &root_hash_len)
				!= SAQ_SUCCESS)
		{
			isc_buffer_free(&root_hash);
			return (ISC_R_NOMEMORY);
		}
		isc_buffer_add(root_hash, root_hash_len);
		if (key->keydata.saq_merkle_tree.root_hash != NULL) {
			isc_buffer_free(&(key->keydata.saq_merkle_tree.root_hash));
		}
		key->keydata.saq_merkle_tree.root_hash = root_hash;
		if (save_merkle_tree(key->keydata.saq_merkle_tree.tree, key->keydata.saq_merkle_tree.meta)
				!= ISC_R_SUCCESS)
		{
			isc_buffer_free(&root_hash);
			key->keydata.saq_merkle_tree.root_hash = NULL;
			return (DST_R_CRYPTOFAILURE);
		}
		return (ISC_R_SUCCESS);
	}
	return (DST_R_CRYPTOFAILURE);
}

static isc_result_t
saqmerkle_finalizesignature(const dst_key_t *key, isc_region_t in, isc_buffer_t *out) {
	isc_result_t ret;
	uint64_t index = 0;
	uint64_t ap_size = 0;
	isc_region_t r;
	SAQ_authentication_path_t *ap = NULL;
	const saq_merkle_alginfo_t *alginfo =
		saqmerkle_alg_info(key->key_alg);
	
	REQUIRE(alginfo != NULL);
	REQUIRE(in.length >= sizeof(uint64_t));
	
	index = *(uint64_t *)in.base;
	if (SAQ_merkle_stream_get_proof(
				key->keydata.saq_merkle_tree.tree,
				index, &ap) != SAQ_SUCCESS)
	{
		DST_RET(DST_R_CRYPTOFAILURE);
	}
	if (SAQ_authentication_path_byte_size(ap, &ap_size) != SAQ_SUCCESS)
	{
		DST_RET(DST_R_CRYPTOFAILURE);
	}
	isc_buffer_availableregion(out, &r);
	if (ap_size > r.length) {
		DST_RET(ISC_R_NOSPACE);
	}
	if (SAQ_authentication_path_serialize(ap, r.base, &ap_size)
			!= SAQ_SUCCESS)
	{
		DST_RET(DST_R_CRYPTOFAILURE);
	}
	isc_buffer_add(out, ap_size);
	ret = ISC_R_SUCCESS;

err:
	if (ap != NULL) {
		SAQ_authentication_path_destroy(&ap);
	}
	return (ret);
}

static isc_result_t
saqmerkle_todns(const dst_key_t *key, isc_buffer_t *data) {
	isc_region_t r;
	const saq_merkle_alginfo_t *alginfo =
		saqmerkle_alg_info(key->key_alg);
	isc_buffer_t *root_hash = key->keydata.saq_merkle_tree.root_hash;

	REQUIRE(alginfo != NULL);
	isc_buffer_availableregion(data, &r);
	INSIST(r.length >= SAQ_SHA256_DIGESTLENGTH);
	if (root_hash == NULL) {
		// This is to allow for findkey to be readable. when a root hash
		// hasn't be generated yet.
		memset(r.base, 0, SAQ_SHA256_DIGESTLENGTH);
		isc_buffer_add(data, SAQ_SHA256_DIGESTLENGTH);
		return (ISC_R_SUCCESS);
	}
	isc_buffer_usedregion(root_hash, &r);
	return isc_buffer_copyregion(data, &r);
}

static isc_result_t
saqmerkle_fromdns(dst_key_t *key, isc_buffer_t *data) {
	isc_result_t ret;
	isc_region_t r;
	isc_buffer_t *root_hash = NULL;
	isc_region_t rhreg;
	const saq_merkle_alginfo_t *alginfo =
		saqmerkle_alg_info(key->key_alg);

	REQUIRE(alginfo != NULL);
	isc_buffer_remainingregion(data, &r);

	if (r.length == 0) {
		return (ISC_R_SUCCESS);
	}
	
	INSIST(r.length == alginfo->root_hash_size);
	isc_buffer_allocate(key->mctx, &root_hash, r.length);

	isc_buffer_availableregion(root_hash, &rhreg);
	if (rhreg.length < r.length) {
		DST_RET(ISC_R_NOSPACE);
	}
	if (isc_buffer_copyregion(root_hash, &r) != ISC_R_SUCCESS) {
		DST_RET(ISC_R_NOSPACE);
	}
	isc_buffer_forward(data, r.length);
	key->keydata.saq_merkle_tree.root_hash = root_hash;
	key->keydata.saq_merkle_tree.tree = NULL;
	key->key_size = r.length * 8;
	isc_mutex_init(&(key->keydata.saq_merkle_tree.lock));
	merkle_meta_init(&(key->keydata.saq_merkle_tree.meta), key, NULL);
	return (ISC_R_SUCCESS);

err:
	if (root_hash != NULL) {
		isc_buffer_free(&root_hash);
	}
	return (ret);
}

static bool
saqmerkle_keypair_isprivate(const dst_key_t *key);

static isc_result_t
saqmerkle_tofile(const dst_key_t *key, const char *directory) {
	dst_private_t priv;
	const saq_merkle_alginfo_t *alginfo =
		saqmerkle_alg_info(key->key_alg);

	REQUIRE(alginfo != NULL);

	if (key->keydata.saq_merkle_tree.tree == NULL)
	{
		return (DST_R_NULLKEY);
	}

	if (key->external) {
		priv.nelements = 0;
		return (dst__privstruct_writefile(key, &priv, directory));
	}

	if (saqmerkle_keypair_isprivate(key)) {
		if (!merkle_meta_dir_is_set(key->keydata.saq_merkle_tree.meta)) {
			merkle_meta_set_dir(key->keydata.saq_merkle_tree.meta, key, directory);
		}
		return save_merkle_tree(key->keydata.saq_merkle_tree.tree, key->keydata.saq_merkle_tree.meta);
	}

	return (DST_R_INVALIDPRIVATEKEY);
}

static isc_result_t
saqmerkle_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	dst_private_t priv;
	isc_result_t ret;
	char *lexer_name;
	char *dir;
	SAQ_merkle_stream_t *tree = NULL;
	isc_buffer_t *root_hash = NULL;
	isc_region_t rhr;
	int i, tree_index = -1;
	uint64_t root_hash_len;
	isc_mem_t *mctx = key->mctx;
	const saq_merkle_alginfo_t *alginfo =
		saqmerkle_alg_info(key->key_alg);

	UNUSED(pub);

	REQUIRE(alginfo != NULL);

	/* read private key file */
	ret = dst__privstruct_parse(key, key->key_alg, lexer, mctx, &priv);
	if (ret != ISC_R_SUCCESS) {
		goto err;
	}

	for (i = 0; i < priv.nelements; i++) {
		switch (priv.elements[i].tag) {
		case TAG_MERKLE_TREE:
			tree_index = i;
			break;
		default:
			break;
		}
	}
	if (tree_index < 0) {
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}

	if (SAQ_merkle_stream_deserialize(
		    priv.elements[tree_index].data, priv.elements[tree_index].length,
		    merkle_ossl_sha256_cb, &tree) != SAQ_SUCCESS)
	{
		DST_RET(ISC_R_NOMEMORY);
	}
	if (SAQ_merkle_stream_get_root_hash_len(tree, &root_hash_len) == SAQ_SUCCESS) {
		isc_buffer_allocate(key->mctx, &root_hash, root_hash_len);
		isc_buffer_availableregion(root_hash, &rhr);
		INSIST(rhr.length >= root_hash_len);
		if (SAQ_merkle_stream_get_root_hash(tree, rhr.base, &root_hash_len)
				!= SAQ_SUCCESS)
		{
			DST_RET(ISC_R_NOMEMORY);
		}
		isc_buffer_add(root_hash, root_hash_len);
	}
	lexer_name = isc_lex_getsourcename(lexer);
	dir = dirname(lexer_name);
	key->keydata.saq_merkle_tree.tree = tree;
	key->keydata.saq_merkle_tree.root_hash = root_hash;
	key->key_size = alginfo->root_hash_size * 8;
	isc_mutex_init(&(key->keydata.saq_merkle_tree.lock));
	merkle_meta_init(&(key->keydata.saq_merkle_tree.meta), key, dir);
	
	dst__privstruct_free(&priv, mctx);
	isc_safe_memwipe(&priv, sizeof(priv));
	return (ISC_R_SUCCESS);
err:
	dst__privstruct_free(&priv, mctx);
	isc_safe_memwipe(&priv, sizeof(priv));

	if (tree != NULL) {
		SAQ_merkle_stream_destroy(&tree);
	}

	if (root_hash != NULL) {
		isc_buffer_free(&root_hash);
	}

	return (ret);
}

static bool
saqmerkle_keypair_compare(const dst_key_t *key1, const dst_key_t *key2) {
	isc_region_t rhr1, rhr2;
	if (key1->keydata.saq_merkle_tree.root_hash != NULL &&
		key2->keydata.saq_merkle_tree.root_hash == NULL) {
		return (false);
	}
	if (key1->keydata.saq_merkle_tree.root_hash == NULL &&
		key2->keydata.saq_merkle_tree.root_hash != NULL) {
		return (false);
	}
	if (key1->keydata.saq_merkle_tree.root_hash != NULL) {
		isc_buffer_usedregion(key1->keydata.saq_merkle_tree.root_hash, &rhr1);
		isc_buffer_usedregion(key2->keydata.saq_merkle_tree.root_hash, &rhr2);
		unsigned char *root_hash1 = rhr1.base;
		unsigned char *root_hash2 = rhr2.base;
		size_t root_hash1_len = rhr1.length;
		size_t root_hash2_len = rhr2.length;

		if (root_hash1_len != root_hash2_len) {
			return (false);
		}
		if (root_hash1 == root_hash2) {
			return (true);
		}

		if (memcmp(root_hash1, root_hash2, root_hash1_len) != 0) {
			return (false);
		}
	}

	/* The private key presence must be same for keys to match. */
	if (saqmerkle_keypair_isprivate(key1) !=
	    saqmerkle_keypair_isprivate(key2))
	{
		return (false);
	}
	return (true);
}

static bool
saqmerkle_keypair_isprivate(const dst_key_t *key) {
	return (key->keydata.saq_merkle_tree.tree != NULL);
}

static void
saqmerkle_tree_destroy(dst_key_t *key) {
	if (saqmerkle_keypair_isprivate(key)) {
		SAQ_merkle_stream_destroy(&key->keydata.saq_merkle_tree.tree);
	}
	if (key->keydata.saq_merkle_tree.root_hash != NULL) {
		isc_buffer_free(&(key->keydata.saq_merkle_tree.root_hash));
	}
	isc_mutex_destroy(&(key->keydata.saq_merkle_tree.lock));
	merkle_meta_destroy(&(key->keydata.saq_merkle_tree.meta));
	key->keydata.saq_merkle_tree.tree = NULL;
	key->keydata.saq_merkle_tree.root_hash = NULL;
}

static dst_func_t saqmerkle_functions = {
	saqmerkle_createctx,
	NULL, /*%< createctx2 */
	saqmerkle_destroyctx,
	saqmerkle_adddata,
	saqmerkle_sign,
	saqmerkle_finalizesignature,
	saqmerkle_verify,
	NULL, /*%< verify2 */
	NULL, /*%< computesecret */
	saqmerkle_keypair_compare,
	NULL, /*%< paramcompare */
	saqmerkle_generate,
	saqmerkle_finalizekey,
	saqmerkle_keypair_isprivate,
	saqmerkle_tree_destroy,
	saqmerkle_todns,
	saqmerkle_fromdns,
	saqmerkle_tofile,
	saqmerkle_parse,
	NULL, /*%< cleanup */
	NULL, /*%< fromlabel */
	NULL, /*%< dump */
	NULL, /*%< restore */
};

isc_result_t
dst__saqmerkle_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL);
	if (*funcp == NULL) {
		*funcp = &saqmerkle_functions;
	}
	return (ISC_R_SUCCESS);
}
