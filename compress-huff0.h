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

#ifndef COMPRESS_HUFF0_H
#define COMPRESS_HUFF0_H

struct sshbuf;

/* The name of the compression method in the key exchange. */
#define COMP_HUFF0_NAME	"huff0@hpnssh.org"

/*
 * Compress the contents of "in" with order-0 Huffman coding (no dictionary,
 * no state kept between calls) and append the result to "out". "in" is not
 * consumed.
 */
int huff0_compress(const struct sshbuf *in, struct sshbuf *out);

/*
 * Reverse huff0_compress(), appending the result to "out". Fails if the input
 * is malformed or would expand to more than "max_out" bytes.
 */
int huff0_uncompress(const struct sshbuf *in, struct sshbuf *out,
    size_t max_out);

#endif /* COMPRESS_HUFF0_H */
