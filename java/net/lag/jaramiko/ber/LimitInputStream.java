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

import java.io.FilterInputStream;
import java.io.InputStream;
import java.io.IOException;


/**
 * An InputStream which can be restricted to allow only a fixed number of
 * bytes to be read before future read operations throw an IOException.
 */
public class LimitInputStream
    extends FilterInputStream
{
    /**
     * Create a new limited InputStream.
     * 
     * @param in the InputStream to wrap
     * @param limit the maximum number of bytes to allow to be read, or -1 to
     *     set no limit
     */
    public
    LimitInputStream (InputStream in, int limit)
    {
        super(in);
        mLimit = limit;
        mCount = 0;
    }
    
    /**
     * Return the number of bytes which can still be read from this stream
     * before hitting the limit. If no limit was set, -1 is always returned.
     * 
     * @return the remaining bytes that can be read, or -1
     */
    public int
    getRemaining ()
    {
        return (mLimit < 0) ? mLimit : mLimit - mCount;
    }
    
    /**
     * Return the total number of bytes that were read from this stream.
     * 
     * @return the number of bytes read
     */
    public int
    getCount ()
    {
        return mCount;
    }
    
    public int
    read ()
        throws IOException
    {
        if ((mLimit >= 0) && (mCount + 1 > mLimit)) {
            return -1;
        }
        int ret = super.read();
        if (ret >= 0) {
            mCount++;
        }
        return ret;
    }
    
    public int
    read (byte[] b)
        throws IOException
    {
        return read(b, 0, b.length);
    }
    
    public int
    read (byte[] b, int off, int len)
        throws IOException
    {
        if ((mLimit >= 0) && (mCount + len > mLimit)) {
            len = mLimit - mCount;
            if (len == 0) {
                return -1;
            }
        }
        
        int ret = super.read(b, off, len);
        if (ret > 0) {
            mCount += ret;
        }
        return ret;
    }
    
    public long
    skip (long n)
        throws IOException
    {
        if ((mLimit >= 0) && (mCount + n > mLimit)) {
            n = mLimit - mCount;
            if (n == 0) {
                return 0;
            }
        }
        
        long ret = super.skip(n);
        if (ret > 0) {
            mCount += ret;
        }
        return ret;
    }
    
    
    private int mLimit;
    private int mCount;
}
