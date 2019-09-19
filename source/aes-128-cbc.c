/*
 * Copyright (C) 2014 Marek Vasut <marex@denx.de>
 * Copyright (C) 2019 Victor Wu <victor_wu@bizlinktech.com>
 *
 * Command for en/de-crypting block of memory with AES-128-CBC cipher.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <aes.h>

#define DIV_ROUND_UP(n, d)(((n) + (d) - 1) / (d))
#define MAX_LEN 4096

static unsigned char sbuf[MAX_LEN];
static unsigned char dbuf[MAX_LEN];

static void help(void)
{
	printf("\nAES 128 CBC\n"
		"\nUsage: aes-128-cbc <enc|dec> <key> <src> <dst> <len>\n"
		"\tenc\tencode\n"
		"\tdec\tdecode\n"
		"\tkey\tkey for this AES algorithm, it must be a 16-byte string\n"
		"\tsrc\tsource file\n"
		"\tdst\tdestination file\n"
		"\tlen\tmax length of data to do this AES algorithm, its value must be a multiple of 16 in hexadecimal\n"
		"\nExample:\n"
		"\nCase 1) encode a 16-byte data\n"
		"\taes-128-cbc enc 1234567890123456 a.txt b.txt 0x10\n"
		"\nCase 2) decode a 16-byte data\n"
		"\taes-128-cbc dec 1234567890123456 b.txt c.txt 0x10\n");
	exit(EXIT_SUCCESS);
}

/**
 * AES-128-CBC
 * @argc:	Command-line argument count
 * @argv:	Array of command-line arguments
 *
 * Returns zero on success, EXIT_FAILURE in case of misuse and negative
 * on error.
 */
int main(int argc, const char *argv[])
{
	uint8_t *key_ptr, *src_ptr, *dst_ptr;
	uint8_t key_exp[AES_EXPAND_KEY_LENGTH];
	uint32_t len, fsize;
	uint32_t aes_blocks;
	int enc;
	FILE *src = NULL, *dst = NULL;
	struct stat src_stat;

	if (argc != 6)
		help();

	if (!strncmp(argv[1], "enc", 3))
		enc = 1;
	else if (!strncmp(argv[1], "dec", 3))
		enc = 0;
	else
		help();

	key_ptr = (uint8_t *)argv[2];

	len = strtoul(argv[5], NULL, 16);
	if (len % 16) {
		printf("len must be a multiple of 16\n");
		return 1;
	}

	if (stat(argv[3], &src_stat)) {
		perror("Cannot get metadata of the source file");
		return -errno;
	}

	if (src_stat.st_size % 16)
		fsize = src_stat.st_size + (16 - src_stat.st_size % 16);
	else
		fsize = src_stat.st_size;

	if (len > fsize) {
		/* data length must be a multiple of 16 */
		if (truncate(argv[3], fsize)) {
			perror("Cannot truncate the source file");
			return -errno;
		}

		len = fsize;
	}

	if (!(src = fopen(argv[3], "r"))) {
		perror("Cannot open the source file");
		return -errno;
	}

	memset(sbuf, 0, MAX_LEN);
	memset(dbuf, 0, MAX_LEN);

	if (fread(sbuf, 1, len, src) < len)
		printf("WARNING: Cannot read length %u bytes from the source file\n", len);

	fclose(src);

	if (!(dst = fopen(argv[4], "w"))) {
		perror("Cannot open the destination file");
		return -errno;
	}

	src_ptr = (uint8_t *)sbuf;
	dst_ptr = (uint8_t *)dbuf;

	/* First we expand the key. */
	aes_expand_key(key_ptr, key_exp);

	/* Calculate the number of AES blocks to encrypt. */
	aes_blocks = DIV_ROUND_UP(len, AES_KEY_LENGTH);

	if (enc)
		aes_cbc_encrypt_blocks(key_exp, src_ptr, dst_ptr, aes_blocks);
	else
		aes_cbc_decrypt_blocks(key_exp, src_ptr, dst_ptr, aes_blocks);

	if (fwrite(dst_ptr, 1, len, dst) < len)
		printf("WARNING: Cannot write length %u bytes to the destination file\n", len);

	fclose(dst);

	return 0;
}
