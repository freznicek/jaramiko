/*
 * Copyright (C) 2006-2007 Robey Pointer <robey@lag.net>
 *
 * This file is part of jaramiko.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package net.lag.jaramiko;

import com.jcraft.jzlib.JZlib;
import com.jcraft.jzlib.ZStream;

/* package */class ZlibCompressor implements Compressor {
    public ZlibCompressor() {
        mInflateStream = new ZStream();
        mInflateStream.inflateInit();
        mDeflateStream = new ZStream();
        mDeflateStream.deflateInit(9);
        mBuffer = new byte[BUFFER_SIZE];
    }

    @Override
    public void finalize() {
        mInflateStream.inflateEnd();
        mInflateStream.free();
        mDeflateStream.deflateEnd();
        mDeflateStream.free();
    }

    /**
     * Create a byte[] by appending two existing buffers. The <code>orig</code>
     * buffer may be <code>null</code>, in which case the <code>add</code>
     * buffer is copied to a new buffer. The returned buffer is always exactly
     * the size of both buffers combined.
     */
    private static byte[] appendBytes(byte[] orig, byte[] add, int offset,
            int length) {
        byte[] out = null;
        int x = 0;
        if (orig == null) {
            out = new byte[length];
            x = 0;
        } else {
            x = orig.length;
            out = new byte[x + length];
            System.arraycopy(orig, 0, out, 0, x);
        }
        System.arraycopy(add, offset, out, x, length);
        return out;
    }

    public byte[] compress(byte[] data, int offset, int length) {
        byte[] out = null;

        /* i'm not a big fan of the ZStream API here. */
        mDeflateStream.next_in = data;
        mDeflateStream.next_in_index = offset;
        mDeflateStream.avail_in = length;

        do {
            mDeflateStream.next_out = mBuffer;
            mDeflateStream.next_out_index = 0;
            mDeflateStream.avail_out = BUFFER_SIZE;
            int status = mDeflateStream.deflate(JZlib.Z_PARTIAL_FLUSH);
            out = appendBytes(out, mBuffer, 0, BUFFER_SIZE
                    - mDeflateStream.avail_out);
            if (status != JZlib.Z_OK) {
                return out;
            }
        } while ((mDeflateStream.avail_in > 0)
                || (mDeflateStream.avail_out == 0));
        return out;
    }

    public byte[] uncompress(byte[] data, int offset, int length) {
        byte[] out = null;

        /* i'm not a big fan of the ZStream API here. */
        mInflateStream.next_in = data;
        mInflateStream.next_in_index = offset;
        mInflateStream.avail_in = length;

        do {
            mInflateStream.next_out = mBuffer;
            mInflateStream.next_out_index = 0;
            mInflateStream.avail_out = BUFFER_SIZE;
            int status = mInflateStream.inflate(JZlib.Z_PARTIAL_FLUSH);
            out = appendBytes(out, mBuffer, 0, BUFFER_SIZE
                    - mInflateStream.avail_out);
            if (status != JZlib.Z_OK) {
                return out;
            }
        } while ((mInflateStream.avail_in > 0)
                || (mInflateStream.avail_out == 0));
        return out;
    }

    private ZStream mDeflateStream;
    private ZStream mInflateStream;
    private byte[] mBuffer;

    private static final int BUFFER_SIZE = 4096;
}
