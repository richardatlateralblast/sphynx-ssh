/*
 * Copyright (c) 2026 Richard Spindler <richard@lateralblast.com.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * huff0@hpnssh.org packet compression.
 *
 * Each packet payload is coded on its own with the Huffman coder from zstd
 * (huff0/), with a new table for every block. Nothing is carried from one
 * packet to the next, so there is no dictionary for one channel's data to
 * leak into another's, which is why OpenSSH made zlib Huffman-only. It is
 * several times faster than zlib in that mode and compresses as well.
 *
 * A payload is a series of blocks, each:
 *
 *	uint8	type		0 stored, 1 huff0
 *	uint32	raw length	1 to HUF_BLOCKSIZE_MAX
 *	uint32	coded length	type 1 only, less than the raw length
 *	byte[]	data		the raw bytes, or the huff0 stream
 *
 * A coded length of 1 is a run of the one byte that follows, as huff0 defines it.
 */

#include "includes.h"

#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "compress-huff0.h"

#include "huff0/huf.h"

#define HUFF0_STORED	0
#define HUFF0_CODED	1

/* Blocks this small are stored; the header would eat the gain. */
#define HUFF0_MIN_BLOCK	64
#define HUFF0_HDR_STORED	5
#define HUFF0_HDR_CODED		9

/* Largest table the decoder may be asked to build (HUF_TABLELOG_MAX). */
#define HUFF0_DTABLE_LOG	12

int
huff0_compress(const struct sshbuf *in, struct sshbuf *out)
{
	const u_char *src = sshbuf_ptr(in);
	size_t left = sshbuf_len(in), n, bound, c;
	u_char *dst;
	int r;
	HUF_CElt ctable[HUF_CTABLE_SIZE_ST(255)];
	U64 wksp[HUF_WORKSPACE_SIZE_U64];
	HUF_repeat repeat;

	while (left > 0) {
		n = left < HUF_BLOCKSIZE_MAX ? left : HUF_BLOCKSIZE_MAX;
		bound = HUFF0_HDR_CODED + HUF_compressBound(n);
		if (bound < HUFF0_HDR_STORED + n)
			bound = HUFF0_HDR_STORED + n;
		if ((r = sshbuf_reserve(out, bound, &dst)) != 0)
			return r;
		c = 0;
		if (n >= HUFF0_MIN_BLOCK) {
			repeat = HUF_repeat_none;
			c = HUF_compress4X_repeat(dst + HUFF0_HDR_CODED, n - 1,
			    src, n, 255, 0 /* default table log */,
			    wksp, sizeof(wksp), ctable, &repeat, 0);
			if (HUF_isError(c) || c >= n)
				c = 0;
		}
		if (c != 0) {
			dst[0] = HUFF0_CODED;
			POKE_U32(dst + 1, n);
			POKE_U32(dst + 5, c);
			c += HUFF0_HDR_CODED;
		} else {
			dst[0] = HUFF0_STORED;
			POKE_U32(dst + 1, n);
			memcpy(dst + HUFF0_HDR_STORED, src, n);
			c = HUFF0_HDR_STORED + n;
		}
		/* give back what the bound reserved and was not used */
		if ((r = sshbuf_consume_end(out, bound - c)) != 0)
			return r;
		src += n;
		left -= n;
	}
	explicit_bzero(wksp, sizeof(wksp));
	return 0;
}

int
huff0_uncompress(const struct sshbuf *in, struct sshbuf *out, size_t max_out)
{
	const u_char *src = sshbuf_ptr(in);
	size_t left = sshbuf_len(in), n, c, d, done = 0;
	u_char *dst;
	int r;
	HUF_DTable dtable[HUF_DTABLE_SIZE(HUFF0_DTABLE_LOG)];
	U64 wksp[HUF_WORKSPACE_SIZE_U64];

	while (left > 0) {
		if (left < HUFF0_HDR_STORED)
			return SSH_ERR_INVALID_FORMAT;
		n = PEEK_U32(src + 1);
		if (n == 0 || n > HUF_BLOCKSIZE_MAX || n > max_out - done)
			return SSH_ERR_INVALID_FORMAT;
		switch (src[0]) {
		case HUFF0_STORED:
			if (left - HUFF0_HDR_STORED < n)
				return SSH_ERR_INVALID_FORMAT;
			if ((r = sshbuf_put(out, src + HUFF0_HDR_STORED,
			    n)) != 0)
				return r;
			src += HUFF0_HDR_STORED + n;
			left -= HUFF0_HDR_STORED + n;
			break;
		case HUFF0_CODED:
			if (left < HUFF0_HDR_CODED)
				return SSH_ERR_INVALID_FORMAT;
			c = PEEK_U32(src + 5);
			if (c == 0 || c >= n || left - HUFF0_HDR_CODED < c)
				return SSH_ERR_INVALID_FORMAT;
			if ((r = sshbuf_reserve(out, n, &dst)) != 0)
				return r;
			if (c == 1) {
				/* a run of one byte; the decoder below does not do these */
				memset(dst, src[HUFF0_HDR_CODED], n);
			} else {
				dtable[0] = (HUF_DTable)(HUFF0_DTABLE_LOG * 0x01000001);
				d = HUF_decompress4X_hufOnly_wksp(dtable, dst, n,
				    src + HUFF0_HDR_CODED, c, wksp, sizeof(wksp), 0);
				if (HUF_isError(d) || d != n)
					return SSH_ERR_INVALID_FORMAT;
			}
			src += HUFF0_HDR_CODED + c;
			left -= HUFF0_HDR_CODED + c;
			break;
		default:
			return SSH_ERR_INVALID_FORMAT;
		}
		done += n;
	}
	return 0;
}
