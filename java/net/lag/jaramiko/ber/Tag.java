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

import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.*;


/**
 * The header of an ASN.1 object. This includes the class (universal,
 * application, context, or private), the type (any integer), and size.
 */
public class Tag
{
    private
    Tag (int domain, int type, int size, boolean isContainer, boolean hasSize)
    {
        mDomain = domain;
        mType = type;
        mSize = size;
        mIsContainer = isContainer;
        mHasSize = hasSize;
    }
    
    public String
    toString ()
    {
        return "<ASN.1 Tag(" + getDomainName(mDomain) + ", " + mType + ", size=" +
            (mHasSize ? Integer.toString(mSize) : "indefinite") + ", container=" +
            (mIsContainer ? "yes" : "no") + ">";
    }
    
    public int
    hashCode ()
    {
        int ret = 0;
        ret = (ret * 37) + mDomain;
        ret = (ret * 37) + mType;
        ret = (ret * 37) + (mIsContainer ? 1 : 0);
        return ret;
    }
    
    public boolean
    equals (Object obj)
    {
        if (obj == null) {
            return false;
        }
        if (! (obj instanceof Tag)) {
            throw new IllegalArgumentException();
        }
        Tag t = (Tag) obj;
        if (t == this) {
            return true;
        }
        return (t.mDomain == mDomain) && (t.mType == mType) && (t.mIsContainer == mIsContainer);
    }
    
    private static Tag
    create (int domain, int type, int size, boolean isContainer, boolean hasSize)
    {
        // these contortions were in case it would make sense to cache Tags.
        // i don't think it does, though.
        return new Tag(domain, type, size, isContainer, hasSize);
    }
    
    public static Tag
    create (int domain, int type)
    {
        return create(domain, type, 0, false, false);
    }
    
    public static Tag
    create (int domain, int type, int size)
    {
        return create(domain, type, size, false, true);
    }
    
    public static Tag
    createContainer (int domain, int type)
    {
        return create(domain, type, 0, true, false);
    }
    
    public static Tag
    createContainer (int domain, int type, int size)
    {
        return create(domain, type, size, true, true);
    }
    
    /**
     * Return a tag of the same domain & type as this one, but with a
     * different value in the size field. This is useful for making a 
     * prototype Tag with all the fields specified, and using it to generate
     * tags of various sizes for writing to streams.
     * 
     * @param size the new size value
     * @return a new Tag, just like this one, but with the specified size
     */
    public Tag
    asSize (int size)
    {
        return Tag.create(mDomain, mType, size, mIsContainer, true);
    }

    /**
     * Read an ASN.1 tag from a stream. This simple implementation limits tag
     * types to 28 bits and size fields to 31 bits, but does support container
     * tags and indefinite-length. If a tag is truncated, an IOException is
     * thrown, but if an EOF occurs before reading any of the tag data, null
     * is returned.
     * 
     * <p>After reading a valid tag and returning it, the stream will be
     * positioned at the first byte after the tag. This will either be the
     * tag's content, or if the size is zero, the beginning of the next tag
     * or EOF.
     * 
     * @param in the stream to read from
     * @return a new Tag read from the stream, or null on EOF
     * @throws IOException if an IOException occurred or the tag was truncated
     */
    public static Tag
    fromStream (InputStream in)
        throws IOException
    {
        int tag = in.read();
        if (tag < 0) {
            // EOF
            return null;
        }
        
        int domain = (tag >> 6);
        boolean isContainer = (tag & 0x20) != 0;
        boolean hasSize = true;
        tag &= 0x1f;
        
        if (tag == 0x1f) {
            // extended form of tag.
            /* in theory, this tag could be an infinite number of bits long.
             * for our simple implementation, we restrict to 28 bits.  that
             * limits us to 256M tags per domain, boo hoo.
             */
            tag = 0;
            int bytes = 0;
            while (true) {
                int t = in.read();
                if (t < 0) {
                    throw new BERException("Truncated ASN.1 tag");
                }
                bytes++;
                tag = (tag << 7) | (t & 0x7f);
                if ((t & 0x80) == 0) {
                    break;
                }
                if (bytes == 4) {
                    throw new BERException("ASN.1 Tag is too long for this simple little library");
                }
            }
        }
        
        int size = in.read();
        if (size < 0) {
            throw new BERException("Truncated ASN.1 tag size");
        }
        if (size == 0x80) {
            hasSize = false;
            size = 0;
            if (! isContainer) {
                throw new BERException("ASN.1 Tag is indefinite-size, non-container (illegal)");
            }
        } else if ((size & 0x80) == 0x80) {
            // extended size field.
            /* in theory, the size field can be an infinite number of bits
             * long. for our simple implementation, we restrict this to 31
             * bits, or 2GB for a single ASN.1 element.
             */
            size &= 0x7f;
            if (size > 4) {
                throw new BERException("ASN.1 Tag size is too long for this simple little library");
            }
            byte[] buffer = new byte[size];
            int count = 0;
            while (count < size) {
                int n = in.read(buffer, count, size - count);
                if (n <= 0) {
                    throw new BERException("Truncated ASN.1 tag size");
                }
                count += n;
            }
            // always positive:
            size = new BigInteger(1, buffer).intValue();
        }
        
        return Tag.create(domain, tag, size, isContainer, hasSize);
    }
    
    public void
    write (OutputStream out)
        throws IOException
    {
        int high_bits = (mDomain << 6);
        if (mIsContainer) {
            high_bits |= 0x20;
        }
        if (mType <= 30) {
            out.write(high_bits | mType);
        } else if (mType <= 127) {
            out.write(high_bits | 0x1f);
            out.write(mType);
        } else {
            out.write(high_bits | 0x1f);
            byte[] buffer = new byte[4];
            int index = 4;
            int type = mType;
            while ((type > 0) || (index == 4)) {
                index--;
                buffer[index] = (byte)((type & 0x7f) | (index == 3 ? 0 : 0x80));
                type >>= 7;
            }
            out.write(buffer, index, 4 - index);
        }
        
        // now, the length.
        if (! mHasSize) {
            out.write(0x80);
        } else if (mSize > 0x7f) {
            byte[] buffer = BigInteger.valueOf(mSize).toByteArray();
            int offset = (buffer[0] == 0 ? 1 : 0);
            out.write(0x80 | (buffer.length - offset));
            out.write(buffer, offset, buffer.length - offset);
        } else {
            out.write(mSize);
        }
    }

    public int
    getDomain ()
    {
        return mDomain;
    }
    
    public int
    getType ()
    {
        return mType;
    }
    
    public int
    getSize ()
    {
        return mSize;
    }
    
    public boolean
    isContainer ()
    {
        return mIsContainer;
    }
    
    public boolean
    hasSize ()
    {
        return mHasSize;
    }
    
    public static String
    getDomainName (int domain)
    {
        switch (domain) {
        case UNIVERSAL:
            return "universal";
        case APPLICATION:
            return "application";
        case CONTEXT:
            return "context";
        case PRIVATE:
            return "private";
        }
        return "invalid";
    }
    
    
    private int mDomain;
    private int mType;
    private int mSize;
    private boolean mIsContainer;
    private boolean mHasSize;
    
    public static final int UNIVERSAL = 0;
    public static final int APPLICATION = 1;
    public static final int CONTEXT = 2;
    public static final int PRIVATE = 3;
    
    public static final Tag TERMINATOR = Tag.create(UNIVERSAL, 0, 0);
}
