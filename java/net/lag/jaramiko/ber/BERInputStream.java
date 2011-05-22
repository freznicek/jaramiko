/*
 * Copyright (C) 2007 Robey Pointer <robey@lag.net>
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

package net.lag.jaramiko.ber;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.*;


public class BERInputStream
{
    public static interface Decoder
    {
        public Object decode (InputStream in, Tag tag) throws IOException;
    }


    public
    BERInputStream (InputStream in)
    {
        mInStream = in;
        mHitEOF = false;
        mAdvanceTag = null;
    }

    public static void
    register (Tag tag, Decoder decoder)
    {
        sDecoderTable.put(tag, decoder);
    }

    /**
     * When reading a container, this method makes sure that the end-of-stream
     * marker (if any) for that container has been read. If not, an exception
     * is thrown. Otherwise, it's a no-op.
     *
     * @throws BERException if the end-of-stream marker was not read yet
     * @throws IOException if there is an exception trying to read the next
     *     BER tag
     */
    public void
    close ()
        throws IOException
    {
        if (hasNext() || ! mHitEOF) {
            throw new BERException("Stream underrun");
        }
    }

    /**
     * Return true if there is another BER element in this stream, and a
     * future call to {@link #next()} should succeed.
     *
     * @return true if there is another BER element in this stream
     *
     * @throws IOException if there is an exception trying to read the next
     *     BER tag
     */
    public boolean
    hasNext ()
        throws IOException
    {
        if (mHitEOF) {
            return false;
        }
        if (mAdvanceTag != null) {
            return true;
        }
        mAdvanceTag = Tag.fromStream(mInStream);
        if ((mAdvanceTag == null) || (mAdvanceTag.equals(Tag.TERMINATOR))) {
            mHitEOF = true;
            return false;
        }
        return (mAdvanceTag != null);
    }

    /**
     * Return the next object from this stream.
     *
     * @throws BERException if there isn't another item in the stream, or
     *     there is no registered decoder for the next item in the stream
     * @throws IOException if there is an exception trying to read the next
     *     BER tag
     */
    public Object
    next ()
        throws IOException
    {
        if (! hasNext()) {
            throw new BERException("End of stream");
        }

        Tag tag = mAdvanceTag;
        mAdvanceTag = null;

        Decoder decoder = (Decoder) sDecoderTable.get(tag);
        if (decoder == null) {
            System.err.println(sDecoderTable);
            throw new BERException("Can't decode object of type " + tag);
        }

        LimitInputStream lis = new LimitInputStream(mInStream, tag.hasSize() ? tag.getSize() : -1);
        Object ret = decoder.decode(lis, tag);
        if (tag.hasSize()) {
            if (lis.getRemaining() > 0) {
                throw new BERException("Stream underrun in decoder for type " + tag);
            }
        }
        return ret;
    }

    public static List
    decodeContainer (InputStream in)
        throws IOException
    {
        List list = new ArrayList();
        BERInputStream subIn = new BERInputStream(in);
        while (subIn.hasNext()) {
            list.add(subIn.next());
        }
        return list;
    }

    /**
     * Decode a block of byte data which is encoded in BER. Only the first
     * encoded object is returned, but if the object is a container, its
     * entire contents will be decoded too. This is just a convenience
     * method.
     *
     * @param data BER-encoded data
     * @return a decoded java object
     * @throws IOException if there was an error in the data
     */
    public static Object
    decode (byte[] data)
        throws IOException
    {
        return new BERInputStream(new ByteArrayInputStream(data)).next();
    }


    private InputStream mInStream;
    private boolean mHitEOF;
    private Tag mAdvanceTag;

    private static Map sDecoderTable = new HashMap();   // Tag -> Decoder

    static {
        CommonCodecs.register();
    }
}
