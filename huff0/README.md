# huff0

The Huffman coder from [zstd](https://github.com/facebook/zstd) 1.5.7 (`huff0`, with the FSE code it uses for its table headers), copied from `lib/` as it is, for the `huff0@hpnssh.org` compression method (`compress-huff0.c`). zstd is available under the BSD licence (`LICENSE.zstd`) or the GPLv2 (`COPYING.zstd`), at your option.

Files: `huf_compress.c`, `huf_decompress.c`, `fse_compress.c`, `fse_decompress.c`, `entropy_common.c`, `hist.c`, `error_private.c`, and the headers they include (`zstd_errors.h` is the one from `lib/`).

Changes from upstream, to make a flat directory build without the rest of zstd:

- The `#include "../common/..."` and `"../zstd_errors.h"` paths now name the file in this directory.
- `huf_decompress.c` no longer includes `zstd_internal.h`, which is not copied. It defines `MIN` itself, the only thing used from it.
- `huf_decompress.c` defines `ZSTD_DISABLE_ASM`, because the x86-64 assembly decoder (`huf_decompress_amd64.S`) is not copied. The C decoder is used on every CPU.

To update, copy the same files from a newer zstd and repeat the changes above.
