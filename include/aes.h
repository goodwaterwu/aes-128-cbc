/*
 * Copyright (c) 2011 The Chromium OS Authors.
 * (C) Copyright 2010 - 2011 NVIDIA Corporation <www.nvidia.com>
 * Copyright (C) 2019 Victor Wu <victor_wu@bizlinktech.com>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef _AES_REF_H_
#define _AES_REF_H_

#include <linux/types.h>

/*
 * AES encryption library, with small code size, supporting only 128-bit AES
 *
 * AES is a stream cipher which works a block at a time, with each block
 * in this case being AES_KEY_LENGTH bytes.
 */

enum {
	AES_STATECOLS	= 4,	/* columns in the state & expanded key */
	AES_KEYCOLS	= 4,	/* columns in a key */
	AES_ROUNDS	= 10,	/* rounds in encryption */

	AES_KEY_LENGTH	= 128 / 8,
	AES_EXPAND_KEY_LENGTH	= 4 * AES_STATECOLS * (AES_ROUNDS + 1),
};

/**
 * aes_expand_key() - Expand the AES key
 *
 * Expand a key into a key schedule, which is then used for the other
 * operations.
 *
 * @key		Key, of length AES_KEY_LENGTH bytes
 * @expkey	Buffer to place expanded key, AES_EXPAND_KEY_LENGTH
 */
void aes_expand_key(__u8 *key, __u8 *expkey);

/**
 * aes_encrypt() - Encrypt single block of data with AES 128
 *
 * @in		Input data
 * @expkey	Expanded key to use for encryption (from aes_expand_key())
 * @out		Output data
 */
void aes_encrypt(__u8 *in, __u8 *expkey, __u8 *out);

/**
 * aes_decrypt() - Decrypt single block of data with AES 128
 *
 * @in		Input data
 * @expkey	Expanded key to use for decryption (from aes_expand_key())
 * @out		Output data
 */
void aes_decrypt(__u8 *in, __u8 *expkey, __u8 *out);

/**
 * Apply chain data to the destination using EOR
 *
 * Each array is of length AES_KEY_LENGTH.
 *
 * @cbc_chain_data	Chain data
 * @src			Source data
 * @dst			Destination data, which is modified here
 */
void aes_apply_cbc_chain_data(__u8 *cbc_chain_data, __u8 *src, __u8 *dst);

/**
 * aes_cbc_encrypt_blocks() - Encrypt multiple blocks of data with AES CBC.
 *
 * @key_exp		Expanded key to use
 * @src			Source data to encrypt
 * @dst			Destination buffer
 * @num_aes_blocks	Number of AES blocks to encrypt
 */
void aes_cbc_encrypt_blocks(__u8 *key_exp, __u8 *src, __u8 *dst, __u32 num_aes_blocks);

/**
 * Decrypt multiple blocks of data with AES CBC.
 *
 * @key_exp		Expanded key to use
 * @src			Source data to decrypt
 * @dst			Destination buffer
 * @num_aes_blocks	Number of AES blocks to decrypt
 */
void aes_cbc_decrypt_blocks(__u8 *key_exp, __u8 *src, __u8 *dst, __u32 num_aes_blocks);

#endif /* _AES_REF_H_ */
