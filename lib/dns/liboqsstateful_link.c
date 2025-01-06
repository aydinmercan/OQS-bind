/*
 * Copyright (C) SandboxAQ and deSEC.
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
#include <oqs/oqs.h>
#include <stdbool.h>

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

typedef struct xmss_tags {
	unsigned int ntags, private_key_tag, public_key_tag;
} xmss_tags_t;

typedef struct oqs_stfl_alginfo {
	xmss_tags_t tags;
	const char *(*oid_to_name)(uint32_t);
	uint32_t (*key_to_oid)(const unsigned char *, size_t);
} oqs_stfl_alginfo_t;

static const oqs_stfl_alginfo_t *
liboqsstateful_alg_info(dst_algorithm_t key_alg) {
	if (key_alg == DST_ALG_XMSS) {
		static const oqs_stfl_alginfo_t xmss_alginfo = {
			.tags = {
				.ntags = OQS_STFL_NTAGS,
				.private_key_tag = TAG_XMSS_PRIVATEKEY,
				.public_key_tag = TAG_XMSS_PUBLICKEY,
			},
			.oid_to_name = xmss_oid_to_name,
			.key_to_oid = xmss_key_to_oid,
		};
		return &xmss_alginfo;
	}
	if (key_alg == DST_ALG_XMSSMT) {
		static const oqs_stfl_alginfo_t xmssmt_alginfo = {
			.tags = {
				.ntags = OQS_STFL_NTAGS,
				.private_key_tag = TAG_XMSSMT_PRIVATEKEY,
				.public_key_tag = TAG_XMSSMT_PUBLICKEY,
			},
			.oid_to_name = xmssmt_oid_to_name,
			.key_to_oid = xmssmt_key_to_oid,
		};
		return &xmssmt_alginfo;
	}
	return NULL;
}

static OQS_STATUS
lock_sk(void *mutex) {
	if (mutex == NULL) {
		return OQS_ERROR;
	}
	isc_mutex_lock((isc_mutex_t *)mutex);
	return OQS_SUCCESS;
}

static OQS_STATUS
unlock_sk(void *mutex) {
	if (mutex == NULL) {
		return OQS_ERROR;
	}
	isc_mutex_unlock((isc_mutex_t *)mutex);
	return OQS_SUCCESS;
}

struct stfl_meta {
	dst_key_t *key;
	char *dir;
};

static void
stfl_meta_init(stfl_meta_t **s, dst_key_t *key, char *directory) {
	if (s == NULL) {
		return;
	}
	stfl_meta_t *sm = isc_mem_get(key->mctx, sizeof(stfl_meta_t));
	sm->key = key;
	if (directory != NULL) {
		sm->dir = isc_mem_strdup(key->mctx, directory);
	} else {
		sm->dir = NULL;
	}
	*s = sm;
}

static void
stfl_meta_destroy(stfl_meta_t **s) {
	if (s == NULL) {
		return;
	}
	stfl_meta_t *sm = *s;
	dst_key_t *key = sm->key;
	if (key != NULL) {
		if (sm->dir != NULL) {
			isc_mem_free(key->mctx, sm->dir);
			sm->dir = NULL;
		}
		isc_mem_put(key->mctx, sm, sizeof(stfl_meta_t));
	}
	*s = NULL;
}

static isc_result_t
keys_to_file(const dst_key_t *key, unsigned char *priv_buf, size_t priv_len,
	     const char *directory) {
	isc_region_t pkr;
	int i = 0;
	const oqs_stfl_alginfo_t *alginfo =
		liboqsstateful_alg_info(key->key_alg);
	REQUIRE(alginfo != NULL);
	dst_private_t priv;
	priv.elements[i].tag = alginfo->tags.private_key_tag;
	priv.elements[i].length = priv_len;
	priv.elements[i].data = priv_buf;
	i++;

	isc_buffer_usedregion(key->keydata.oqs_stfl_keypair.pub, &pkr);
	INSIST(pkr.length ==
	       key->keydata.oqs_stfl_keypair.ctx->length_public_key);

	priv.elements[i].tag = alginfo->tags.public_key_tag;
	priv.elements[i].length = pkr.length;
	priv.elements[i].data = pkr.base;
	i++;
	priv.nelements = i;
	return dst__privstruct_writefile(key, &priv, directory);
}

static OQS_STATUS
save_secret_key(unsigned char *key_buf, size_t buf_len, void *context) {
	stfl_meta_t *meta = (stfl_meta_t *)context;
	if (keys_to_file(meta->key, key_buf, buf_len, meta->dir) !=
	    ISC_R_SUCCESS)
	{
		return OQS_ERROR;
	}
	return OQS_SUCCESS;
}

static isc_result_t
liboqsstateful_createctx(dst_key_t *key, dst_context_t *dctx) {
	isc_buffer_t *buf = NULL;
	const oqs_stfl_alginfo_t *alginfo =
		liboqsstateful_alg_info(dctx->key->key_alg);

	UNUSED(key);

	REQUIRE(alginfo != NULL);

	isc_buffer_allocate(dctx->mctx, &buf, 64);
	dctx->ctxdata.generic = buf;

	return ISC_R_SUCCESS;
}

static void
liboqsstateful_destroyctx(dst_context_t *dctx) {
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	const oqs_stfl_alginfo_t *alginfo =
		liboqsstateful_alg_info(dctx->key->key_alg);

	REQUIRE(alginfo != NULL);

	if (buf != NULL) {
		isc_buffer_free(&buf);
	}
	dctx->ctxdata.generic = NULL;
}

static isc_result_t
liboqsstateful_adddata(dst_context_t *dctx, const isc_region_t *data) {
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	isc_buffer_t *nbuf = NULL;
	isc_region_t r;
	unsigned int length;
	isc_result_t result;
	const oqs_stfl_alginfo_t *alginfo =
		liboqsstateful_alg_info(dctx->key->key_alg);

	REQUIRE(alginfo != NULL);

	result = isc_buffer_copyregion(buf, data);
	if (result == ISC_R_SUCCESS) {
		return ISC_R_SUCCESS;
	}

	length = isc_buffer_length(buf) + data->length + 64;
	isc_buffer_allocate(dctx->mctx, &nbuf, length);
	isc_buffer_usedregion(buf, &r);
	(void)isc_buffer_copyregion(nbuf, &r);
	(void)isc_buffer_copyregion(nbuf, data);
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = nbuf;

	return ISC_R_SUCCESS;
}

static isc_result_t
liboqsstateful_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_result_t ret;
	dst_key_t *key = dctx->key;
	isc_region_t tbsreg;
	isc_region_t sigreg;
	OQS_SIG_STFL_SECRET_KEY *priv_key = key->keydata.oqs_stfl_keypair.priv;
	OQS_SIG_STFL *sig_ctx = key->keydata.oqs_stfl_keypair.ctx;
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	size_t siglen;
	const oqs_stfl_alginfo_t *alginfo =
		liboqsstateful_alg_info(key->key_alg);

	REQUIRE(alginfo != NULL);
	siglen = sig_ctx->length_signature;
	isc_buffer_availableregion(sig, &sigreg);
	if (sigreg.length < (unsigned int)siglen) {
		DST_RET(ISC_R_NOSPACE);
	}

	isc_buffer_usedregion(buf, &tbsreg);
	if (OQS_SIG_STFL_sign(sig_ctx, sigreg.base, &siglen, tbsreg.base,
			      tbsreg.length, priv_key) != OQS_SUCCESS)
	{
		DST_RET(dst__openssl_toresult3(dctx->category,
					       "OQS_SIG_STFL_sign",
					       DST_R_SIGNFAILURE));
	}
	INSIST(siglen <= sig_ctx->length_signature);
	isc_buffer_add(sig, (unsigned int)siglen);
	ret = ISC_R_SUCCESS;

err:
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return ret;
}

static isc_result_t
liboqsstateful_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_result_t ret;
	dst_key_t *key = dctx->key;
	isc_region_t tbsreg, pkreg;
	isc_buffer_t *pub_key = key->keydata.oqs_stfl_keypair.pub;
	OQS_SIG_STFL *sig_ctx = key->keydata.oqs_stfl_keypair.ctx;
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	const oqs_stfl_alginfo_t *alginfo =
		liboqsstateful_alg_info(key->key_alg);
	REQUIRE(alginfo != NULL);

	if (sig->length > sig_ctx->length_signature) {
		DST_RET(DST_R_VERIFYFAILURE);
	}
	isc_buffer_usedregion(buf, &tbsreg);
	isc_buffer_usedregion(pub_key, &pkreg);

	if (OQS_SIG_STFL_verify(sig_ctx, tbsreg.base, tbsreg.length, sig->base,
				sig->length, pkreg.base) != OQS_SUCCESS)
	{
		DST_RET(DST_R_VERIFYFAILURE);
	}
	ret = ISC_R_SUCCESS;
err:
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return ret;
}

static isc_result_t
liboqsstateful_generate(dst_key_t *key, int oid, void (*callback)(int)) {
	isc_result_t ret;
	OQS_SIG_STFL_SECRET_KEY *priv_key = NULL;
	OQS_SIG_STFL *sig_ctx = NULL;
	isc_buffer_t *pub_key = NULL;
	isc_region_t pkreg;
	size_t pub_len;
	const oqs_stfl_alginfo_t *alginfo =
		liboqsstateful_alg_info(key->key_alg);
	const char *xmss_name;
	UNUSED(callback);

	REQUIRE(alginfo != NULL);

	xmss_name = alginfo->oid_to_name((uint32_t)oid);
	sig_ctx = OQS_SIG_STFL_new(xmss_name);
	REQUIRE(sig_ctx != NULL);

	priv_key = OQS_SIG_STFL_SECRET_KEY_new(sig_ctx->method_name);
	if (priv_key == NULL) {
		DST_RET(DST_R_CRYPTOFAILURE);
	}

	pub_len = sig_ctx->length_public_key;
	isc_buffer_allocate(key->mctx, &pub_key, pub_len);
	isc_buffer_availableregion(pub_key, &pkreg);
	if (pkreg.length < pub_len) {
		DST_RET(ISC_R_NOSPACE);
	}

	if (OQS_SIG_STFL_keypair(sig_ctx, pkreg.base, priv_key) != OQS_SUCCESS)
	{
		DST_RET(DST_R_CRYPTOFAILURE);
	}
	isc_buffer_add(pub_key, (unsigned int)pub_len);

	key->key_size = sig_ctx->length_public_key * 8;
	key->keydata.oqs_stfl_keypair.priv = priv_key;
	key->keydata.oqs_stfl_keypair.pub = pub_key;
	key->keydata.oqs_stfl_keypair.ctx = sig_ctx;
	isc_mutex_init(&(key->keydata.oqs_stfl_keypair.lock));
	stfl_meta_init(&(key->keydata.oqs_stfl_keypair.meta), key, NULL);
	ret = ISC_R_SUCCESS;

	return ret;

err:
	if (pub_key != NULL) {
		isc_buffer_free(&pub_key);
	}

	if (priv_key != NULL) {
		OQS_SIG_STFL_SECRET_KEY_free(priv_key);
	}

	if (sig_ctx != NULL) {
		OQS_SIG_STFL_free(sig_ctx);
	}

	return ret;
}

static isc_result_t
liboqsstateful_todns(const dst_key_t *key, isc_buffer_t *data) {
	isc_region_t r;
	const oqs_stfl_alginfo_t *alginfo =
		liboqsstateful_alg_info(key->key_alg);
	isc_buffer_t *pub_key = key->keydata.oqs_stfl_keypair.pub;

	REQUIRE(alginfo != NULL);
	REQUIRE(pub_key != NULL);
	isc_buffer_usedregion(pub_key, &r);
	if (r.length > isc_buffer_length(data)) {
		return ISC_R_NOSPACE;
	}
	return isc_buffer_copyregion(data, &r);
}

static isc_result_t
liboqsstateful_fromdns(dst_key_t *key, isc_buffer_t *data) {
	isc_result_t ret;
	isc_region_t r;
	const char *xmss_name;
	uint32_t oid = 0;
	OQS_SIG_STFL *sig_ctx = NULL;
	isc_buffer_t *pub_key = NULL;
	isc_region_t pkreg;
	const oqs_stfl_alginfo_t *alginfo =
		liboqsstateful_alg_info(key->key_alg);

	REQUIRE(alginfo != NULL);

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return ISC_R_SUCCESS;
	}
	oid = alginfo->key_to_oid(r.base, r.length);
	if (oid == 0) {
		DST_RET(DST_R_CRYPTOFAILURE);
	}
	xmss_name = alginfo->oid_to_name(oid);
	sig_ctx = OQS_SIG_STFL_new(xmss_name);
	if (sig_ctx == NULL) {
		DST_RET(DST_R_CRYPTOFAILURE);
	}
	isc_buffer_allocate(key->mctx, &pub_key, r.length);

	isc_buffer_availableregion(pub_key, &pkreg);
	if (pkreg.length < r.length) {
		DST_RET(ISC_R_NOSPACE);
	}
	isc_buffer_copyregion(pub_key, &r);

	isc_buffer_forward(data, r.length);
	key->keydata.oqs_stfl_keypair.pub = pub_key;
	key->keydata.oqs_stfl_keypair.priv = NULL;
	key->keydata.oqs_stfl_keypair.ctx = sig_ctx;
	key->key_size = r.length * 8;
	stfl_meta_init(&(key->keydata.oqs_stfl_keypair.meta), key, NULL);
	isc_mutex_init(&(key->keydata.oqs_stfl_keypair.lock));
	return ISC_R_SUCCESS;

err:
	if (pub_key != NULL) {
		isc_buffer_free(&pub_key);
	}

	if (sig_ctx != NULL) {
		OQS_SIG_STFL_free(sig_ctx);
	}

	return ret;
}

static bool
liboqsstateful_keypair_isprivate(const dst_key_t *key);

static isc_result_t
liboqsstateful_tofile(const dst_key_t *key, const char *directory) {
	isc_result_t ret;
	dst_private_t priv;
	unsigned char *privbuf = NULL, *pubbuf = NULL;
	size_t privlen = 0, publen = 0;
	const oqs_stfl_alginfo_t *alginfo =
		liboqsstateful_alg_info(key->key_alg);

	REQUIRE(alginfo != NULL);

	if (key->keydata.oqs_stfl_keypair.pub == NULL ||
	    key->keydata.oqs_stfl_keypair.priv == NULL)
	{
		return DST_R_NULLKEY;
	}

	if (key->external) {
		priv.nelements = 0;
		return dst__privstruct_writefile(key, &priv, directory);
	}

	if (liboqsstateful_keypair_isprivate(key)) {
		if (OQS_SIG_STFL_SECRET_KEY_serialize(
			    &privbuf, &privlen,
			    key->keydata.oqs_stfl_keypair.priv) != OQS_SUCCESS)
		{
			return ISC_R_NOMEMORY;
		}
		ret = keys_to_file(key, privbuf, privlen, directory);
	}

	if (privbuf != NULL) {
		OQS_MEM_secure_free(privbuf, privlen);
	}
	if (pubbuf != NULL) {
		isc_mem_put(key->mctx, pubbuf, publen);
	}
	return ret;
}

static isc_result_t
liboqsstateful_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	dst_private_t priv;
	isc_result_t ret;
	const char *xmss_name;
	char *lexer_name;
	char *dir;
	uint32_t oid;
	OQS_SIG_STFL_SECRET_KEY *priv_key = NULL;
	OQS_SIG_STFL *sig_ctx = NULL;
	isc_buffer_t *pub_key = NULL;
	int i, privkey_index = -1, pubkey_index = -1;
	size_t pub_len, priv_len;
	isc_mem_t *mctx = key->mctx;
	const oqs_stfl_alginfo_t *alginfo =
		liboqsstateful_alg_info(key->key_alg);

	UNUSED(pub);

	REQUIRE(alginfo != NULL);

	/* read private key file */
	ret = dst__privstruct_parse(key, key->key_alg, lexer, mctx, &priv);
	if (ret != ISC_R_SUCCESS) {
		goto err;
	}

	for (i = 0; i < priv.nelements; i++) {
		switch (priv.elements[i].tag) {
		case TAG_XMSS_PRIVATEKEY:
		case TAG_XMSSMT_PRIVATEKEY:
			privkey_index = i;
			break;
		case TAG_XMSS_PUBLICKEY:
		case TAG_XMSSMT_PUBLICKEY:
			pubkey_index = i;
			break;
		default:
			break;
		}
	}
	if (privkey_index < 0 || pubkey_index < 0) {
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}
	priv_len = priv.elements[privkey_index].length;
	pub_len = priv.elements[pubkey_index].length;
	oid = xmss_key_to_oid(priv.elements[pubkey_index].data, pub_len);
	if (oid == 0) {
		DST_RET(DST_R_CRYPTOFAILURE);
	}
	xmss_name = alginfo->oid_to_name(oid);

	priv_key = OQS_SIG_STFL_SECRET_KEY_new(xmss_name);
	if (priv_key == NULL) {
		DST_RET(ISC_R_NOMEMORY);
	}
	sig_ctx = OQS_SIG_STFL_new(xmss_name);
	INSIST(priv_len == sig_ctx->length_secret_key);
	INSIST(pub_len == sig_ctx->length_public_key);
	if (OQS_SIG_STFL_SECRET_KEY_deserialize(
		    priv_key, priv.elements[privkey_index].data, priv_len,
		    NULL) != OQS_SUCCESS)
	{
		DST_RET(ISC_R_NOMEMORY);
	}
	isc_buffer_allocate(key->mctx, &pub_key, pub_len);
	isc_buffer_putmem(pub_key, priv.elements[pubkey_index].data, pub_len);

	OQS_SIG_STFL_SECRET_KEY_SET_lock(priv_key, lock_sk);
	OQS_SIG_STFL_SECRET_KEY_SET_unlock(priv_key, unlock_sk);
	OQS_SIG_STFL_SECRET_KEY_SET_mutex(
		priv_key, &(key->keydata.oqs_stfl_keypair.lock));
	lexer_name = isc_lex_getsourcename(lexer);
	dir = dirname(lexer_name);
	stfl_meta_init(&(key->keydata.oqs_stfl_keypair.meta), key, dir);
	OQS_SIG_STFL_SECRET_KEY_SET_store_cb(
		priv_key, save_secret_key, key->keydata.oqs_stfl_keypair.meta);
	key->keydata.oqs_stfl_keypair.priv = priv_key;
	key->keydata.oqs_stfl_keypair.pub = pub_key;
	key->keydata.oqs_stfl_keypair.ctx = sig_ctx;
	key->key_size = pub_len * 8;
	isc_mutex_init(&(key->keydata.oqs_stfl_keypair.lock));

	dst__privstruct_free(&priv, mctx);
	isc_safe_memwipe(&priv, sizeof(priv));
	return ret;
err:
	dst__privstruct_free(&priv, mctx);

	if (priv_key != NULL) {
		isc_safe_memwipe(&priv, sizeof(priv));
		OQS_MEM_secure_free(priv_key, sizeof(*priv_key));
	}

	if (pub_key != NULL) {
		isc_mem_free(key->mctx, pub_key);
	}

	if (sig_ctx != NULL) {
		OQS_SIG_STFL_free(sig_ctx);
	}

	return ret;
}

static bool
liboqsstateful_keypair_compare(const dst_key_t *key1, const dst_key_t *key2) {
	isc_region_t kr1, kr2;
	isc_buffer_usedregion(key1->keydata.oqs_stfl_keypair.pub, &kr1);
	isc_buffer_usedregion(key2->keydata.oqs_stfl_keypair.pub, &kr2);
	unsigned char *pub_key1 = kr1.base;
	unsigned char *pub_key2 = kr2.base;
	size_t key_len = kr1.length;
	size_t key2_len = kr2.length;

	if (key2_len != key_len) {
		return false;
	}
	if (pub_key1 == pub_key2) {
		return true;
	}

	if (memcmp(pub_key1, pub_key2, key_len) != 0) {
		return false;
	}

	/* The private key presence must be same for keys to match. */
	if (liboqsstateful_keypair_isprivate(key1) !=
	    liboqsstateful_keypair_isprivate(key2))
	{
		return false;
	}
	return true;
}

static bool
liboqsstateful_keypair_isprivate(const dst_key_t *key) {
	return key->keydata.oqs_stfl_keypair.priv != NULL;
}

static void
liboqsstateful_keypair_destroy(dst_key_t *key) {
	if (liboqsstateful_keypair_isprivate(key)) {
		OQS_SIG_STFL_SECRET_KEY_free(
			key->keydata.oqs_stfl_keypair.priv);
	}
	if (key->keydata.oqs_stfl_keypair.ctx != NULL) {
		OQS_SIG_STFL_free(key->keydata.oqs_stfl_keypair.ctx);
	}
	if (key->keydata.oqs_stfl_keypair.pub != NULL) {
		isc_buffer_free(&(key->keydata.oqs_stfl_keypair.pub));
	}
	isc_mutex_destroy(&(key->keydata.oqs_stfl_keypair.lock));
	stfl_meta_destroy(&(key->keydata.oqs_stfl_keypair.meta));
	key->keydata.oqs_stfl_keypair.pub = NULL;
	key->keydata.oqs_stfl_keypair.priv = NULL;
	key->keydata.oqs_stfl_keypair.ctx = NULL;
}

static dst_func_t liboqsstateful_functions = {
	liboqsstateful_createctx,
	NULL, /*%< createctx2 */
	liboqsstateful_destroyctx,
	liboqsstateful_adddata,
	liboqsstateful_sign,
	NULL, /*%< finalizesignature */
	liboqsstateful_verify,
	NULL, /*%< verify2 */
	NULL, /*%< computesecret */
	liboqsstateful_keypair_compare,
	NULL, /*%< paramcompare */
	liboqsstateful_generate,
	NULL, /*%< finalizekey */
	liboqsstateful_keypair_isprivate,
	liboqsstateful_keypair_destroy,
	liboqsstateful_todns,
	liboqsstateful_fromdns,
	liboqsstateful_tofile,
	liboqsstateful_parse,
	NULL, /*%< cleanup */
	NULL, /*%< fromlabel */
	NULL, /*%< dump */
	NULL, /*%< restore */
};

isc_result_t
dst__liboqsstateful_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL);
	if (*funcp == NULL) {
		*funcp = &liboqsstateful_functions;
	}
	return ISC_R_SUCCESS;
}
