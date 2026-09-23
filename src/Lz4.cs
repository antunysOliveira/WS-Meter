// ==================== LZ4 Block-format Decoder ====================
//
// Confirmed by static RE of warspear.exe (2026-09-21, docs/CLIENT-RE-R5.md).
// Function FUN_005498a0 in client decompresses tag=492 payload as LZ4.
//
// Wire tag=492 body:
//   [varint N] [N bytes LZ4 compressed] [u32 uncompressed_size]
//
// This module implements LZ4 BLOCK format only (no frame magic, no framing header).
// Reference: LZ4 block spec (https://github.com/lz4/lz4/wiki/lz4_Block_format.md).
// Written from spec, no library code copied.

using System;

namespace WSEngine
{
    public static class Lz4
    {
        // Decompress LZ4 block bytes into a buffer of exactly expectedSize bytes.
        // Throws on truncation, invalid offset, or size mismatch. Never reads/writes past bounds.
        public static byte[] DecompressBlock(byte[] src, int srcOffset, int srcLen, int expectedSize)
        {
            if (src == null) throw new ArgumentNullException("src");
            if (srcOffset < 0 || srcLen < 0 || srcOffset + srcLen > src.Length)
                throw new ArgumentException("bad src range");
            if (expectedSize < 0) throw new ArgumentException("bad expectedSize");
            if (expectedSize == 0)
            {
                if (srcLen != 0) throw new Exception("lz4: expectedSize==0 but srcLen>0");
                return new byte[0];
            }

            byte[] dst = new byte[expectedSize];
            int sPos = srcOffset;
            int sEnd = srcOffset + srcLen;
            int dPos = 0;

            while (sPos < sEnd)
            {
                int token = src[sPos++];
                int litLen = token >> 4;
                int matchLen = token & 0xf;

                // Extended literal length
                if (litLen == 15)
                {
                    while (true)
                    {
                        if (sPos >= sEnd) throw new Exception("lz4: truncated during lit-ext");
                        byte b = src[sPos++];
                        litLen += b;
                        if (b != 0xff) break;
                        if (litLen < 0) throw new Exception("lz4: lit-len overflow");
                    }
                }

                // Copy literals
                if (litLen > 0)
                {
                    if (sPos + litLen > sEnd) throw new Exception("lz4: literals overrun src");
                    if (dPos + litLen > expectedSize) throw new Exception("lz4: literals overrun dst");
                    Buffer.BlockCopy(src, sPos, dst, dPos, litLen);
                    sPos += litLen;
                    dPos += litLen;
                }

                // Last sequence has only literals (no match). If we're at end, done.
                if (sPos >= sEnd) break;

                // Match offset (u16 LE)
                if (sPos + 2 > sEnd) throw new Exception("lz4: truncated match offset");
                int offset = src[sPos] | (src[sPos + 1] << 8);
                sPos += 2;
                if (offset == 0) throw new Exception("lz4: zero match offset");
                if (offset > dPos) throw new Exception("lz4: match offset before start (offset=" + offset + " dPos=" + dPos + ")");

                // Extended match length
                if (matchLen == 15)
                {
                    while (true)
                    {
                        if (sPos >= sEnd) throw new Exception("lz4: truncated during match-ext");
                        byte b = src[sPos++];
                        matchLen += b;
                        if (b != 0xff) break;
                        if (matchLen < 0) throw new Exception("lz4: match-len overflow");
                    }
                }
                matchLen += 4;   // MINMATCH

                if (dPos + matchLen > expectedSize) throw new Exception("lz4: match overrun dst (matchLen=" + matchLen + " remaining=" + (expectedSize - dPos) + ")");

                // Copy match — byte-by-byte because match regions can overlap
                // (offset < matchLen is common in RLE-like sequences).
                int matchStart = dPos - offset;
                for (int i = 0; i < matchLen; i++) dst[dPos + i] = dst[matchStart + i];
                dPos += matchLen;
            }

            if (dPos != expectedSize)
                throw new Exception("lz4: size mismatch: produced=" + dPos + " expected=" + expectedSize);
            return dst;
        }
    }
}
