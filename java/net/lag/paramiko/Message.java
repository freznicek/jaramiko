/*
 * Copyright (C) 2005 Robey Pointer <robey@lag.net>
 *
 * This file is part of paramiko.
 *
 * Paramiko is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * Paramiko is distrubuted in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Paramiko; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 * 
 * 
 * Created on May 7, 2005
 */

package net.lag.paramiko;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;


/**
 * @author robey
 */
public final class Message
{
    public
    Message ()
    {
        // start at position 5 to leave space for packetization
        init(new byte[DEFAULT_SIZE], 5, 0, 0);
    }
    
    public
    Message (byte[] buf)
    {
        init(buf, 0, buf.length, 0);
    }
    
    /**
     * Create a Message from an existing byte array, extending only for a
     * subrange of the array, with a specific sequence number.  No data from
     * beyond the given length will be read or written, but if an attempt is
     * made, the internal buffer will be replaced with a newly-allocated
     * array.  This method allows you to wrap a byte array into a Message,
     * avoiding allocation in the normal case.
     * 
     * @param buf the byte array to wrap
     * @param position the starting position of data in the array
     * @param length the number of bytes to include in the Message
     * @param sequence an arbitrary "sequence number" to track
     */
    public
    Message (byte[] buf, int position, int length, int sequence)
    {
        init(buf, position, length, sequence);
    }
    
    private void
    init (byte[] buf, int position, int length, int sequence)
    {
        mBuffer = buf;
        mStart = position;
        mPosition = position;
        mLength = length;
        mSequenceNumber = sequence;
    }

    public byte[]
    toByteArray ()
    {
        if (mStart == 0) {
            return mBuffer;
        }
        
        byte[] out = new byte[mPosition - mStart];
        System.arraycopy(mBuffer, mStart, out, 0, mPosition - mStart);
        return out;
    }
    
    public int
    getPosition ()
    {
        return mPosition - mStart;
    }
    
    public void
    setPosition (int position)
    {
        mPosition = position + mStart;
    }
    
    public int
    getLength ()
    {
        if (mLength > 0) {
            return mLength;
        }
        return mBuffer.length;
    }
    
    public void
    putByte (byte b)
    {
        ensureSpace(1);
        mBuffer[mPosition++] = b;
    }
    
    public void
    putBytes (byte[] b)
    {
        ensureSpace(b.length);
        System.arraycopy(b, 0, mBuffer, mPosition, b.length);
        mPosition += b.length;
    }
    
    public void
    putBoolean (boolean b)
    {
        putByte(b ? (byte)1 : (byte)0);
    }
    
    public void
    putInt (int i)
    {
        ensureSpace(4);
        mBuffer[mPosition++] = (byte)((i >> 24) & 0xff);
        mBuffer[mPosition++] = (byte)((i >> 16) & 0xff);
        mBuffer[mPosition++] = (byte)((i >> 8) & 0xff);
        mBuffer[mPosition++] = (byte)(i & 0xff);
    }
    
    public void
    putInt64 (long l)
    {
        ensureSpace(8);
        mBuffer[mPosition++] = (byte)((l >> 56) & 0xff);
        mBuffer[mPosition++] = (byte)((l >> 48) & 0xff);
        mBuffer[mPosition++] = (byte)((l >> 40) & 0xff);
        mBuffer[mPosition++] = (byte)((l >> 32) & 0xff);
        mBuffer[mPosition++] = (byte)((l >> 24) & 0xff);
        mBuffer[mPosition++] = (byte)((l >> 16) & 0xff);
        mBuffer[mPosition++] = (byte)((l >> 8) & 0xff);
        mBuffer[mPosition++] = (byte)(l & 0xff);
    }
    
    public void
    putMPZ (BigInteger bi)
    {
        byte[] b = bi.toByteArray();
        ensureSpace(4 + b.length);
        putInt(b.length);
        System.arraycopy(b, 0, mBuffer, mPosition, b.length);
        mPosition += b.length;
    }
    
    public void
    putString (String s)
    {
        byte[] b;
        try {
            b = s.getBytes("UTF-8");
        } catch (UnsupportedEncodingException x) {
            b = "<encoding error>".getBytes();
        }
        ensureSpace(4 + b.length);
        putInt(b.length);
        System.arraycopy(b, 0, mBuffer, mPosition, b.length);
        mPosition += b.length;
    }
    
    public void
    putList (List l)
    {
        StringBuffer out = new StringBuffer();
        for (Iterator i = l.iterator(); i.hasNext(); ) {
            String s = i.next().toString();
            out.append(s);
            out.append(',');
        }
        if (out.length() > 0) {
            // remove trailing comma
            out.setLength(out.length() - 1);
        }
        putString(out.toString());
    }
    
    public byte
    getByte ()
    {
        ensureSpace(1);
        return mBuffer[mPosition++];
    }
    
    public byte[]
    getBytes (int n)
    {
        ensureSpace(n);
        byte[] out = new byte[n];
        System.arraycopy(mBuffer, mPosition, out, 0, n);
        mPosition += n;
        return out;
    }
    
    public boolean
    getBoolean ()
    {
        ensureSpace(1);
        return (mBuffer[mPosition++] != 0);
    }
    
    public int
    getInt ()
    {
        ensureSpace(4);
        return (((int) mBuffer[mPosition++] & 0xff) << 24) |
            (((int) mBuffer[mPosition++] & 0xff) << 16) |
            (((int) mBuffer[mPosition++] & 0xff) << 8) |
            ((int) mBuffer[mPosition++] & 0xff);
    }

    public long
    getInt64 ()
    {
        ensureSpace(8);
        return (((long) mBuffer[mPosition++] & 0xff) << 56) |
            (((long) mBuffer[mPosition++] & 0xff) << 48) |
            (((long) mBuffer[mPosition++] & 0xff) << 40) |
            (((long) mBuffer[mPosition++] & 0xff) << 32) |
            (((long) mBuffer[mPosition++] & 0xff) << 24) |
            (((long) mBuffer[mPosition++] & 0xff) << 16) |
            (((long) mBuffer[mPosition++] & 0xff) << 8) |
            ((long) mBuffer[mPosition++] & 0xff);        
    }
    
    public BigInteger
    getMPZ ()
    {
        int len = getInt();
        byte[] b = new byte[len];
        ensureSpace(len);
        System.arraycopy(mBuffer, mPosition, b, 0, len);
        mPosition += len;
        return new BigInteger(b);
    }
    
    public String
    getString ()
    {
        int len = getInt();
        byte[] b = new byte[len];
        ensureSpace(len);
        System.arraycopy(mBuffer, mPosition, b, 0, len);
        mPosition += len;
        try {
            return new String(b, "UTF-8");
        } catch (UnsupportedEncodingException x) {
            return "<encoding error>";
        }
    }
    
    public List
    getList ()
    {
        return Arrays.asList(getString().split(","));
    }
    
    /**
     * Pack the SSH2 message into a proper SSH2 packet, with its length being
     * a whole multiple of the given block size.  Padding is added from the
     * secure random generator.  Normally you only want to call this method
     * once.
     * 
     * @param random a source of secure random bytes (used for padding)
     * @param blockSize the block size to pad up to
     */
    public void
    packetize (SecureRandom random, int blockSize)
    {
        // pad up at least 4 bytes, to nearest block-size (usually 8)
        int padding = 3 + blockSize - ((mPosition - mStart + 8) % blockSize);
        byte[] pad = new byte[padding];
        random.nextBytes(pad);

        if (mStart < 5) {
            // push everything forward 5 bytes, so we have room for a header
            ensureSpace(5);
            System.arraycopy(mBuffer, mStart, mBuffer, mStart + 5, mPosition - mStart);
            mStart += 5;
            mPosition += 5;
        }
        
        // add 5-byte prefix
        int oldpos = mPosition;
        int size = mPosition - mStart;
        mPosition = mStart - 5;
        putInt(size + padding + 1);
        putByte((byte) padding);

        mStart -= 5;
        mPosition = oldpos;
        ensureSpace(padding);
        System.arraycopy(pad, 0, mBuffer, mPosition, padding);
        mPosition += padding;
    }
    
    private void
    ensureSpace (int n)
    {
        int max = mBuffer.length;
        if ((mLength > 0) && (mLength + mStart < max)) {
            max = mLength + mStart; 
        }
        if (mPosition + n > max) {
            // expand
            int newlen = max * 4;
            while (mPosition + n > newlen) {
                newlen *= 4;
            }
            byte[] newbuf = new byte[newlen];
            System.arraycopy(mBuffer, 0, newbuf, 0, mPosition);
            mBuffer = newbuf;
            mLength = 0;
        }
    }

    
    private byte[] mBuffer;
    private int mPosition = 0;
    private int mStart = 0;
    private int mLength = 0;
    private int mSequenceNumber = 0;
    
    // default size of the buffer, expanded as needed
    private static final int DEFAULT_SIZE = 64;
}
