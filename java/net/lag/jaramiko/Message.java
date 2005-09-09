/*
 * Copyright (C) 2005 Robey Pointer <robey@lag.net>
 *
 * This file is part of paramiko.
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
 * 
 * 
 * Created on May 7, 2005
 */

package net.lag.jaramiko;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import net.lag.crai.CraiRandom;


/**
 * SSH2's basic protocol unit, a byte stream that can encode ints, longs,
 * strings, booleans, bytes, and BigIntegers.  This class can build or parse
 * such streams.
 * 
 * @author robey
 */
public final class Message
{
    /**
     * Create a new empty Message, suitable for writing.
     */
    public
    Message ()
    {
        // start at position 5 to leave space for packetization
        init(new byte[DEFAULT_SIZE], 5, 0, 0);
    }
    
    /**
     * Create a Message from a byte stream, suitable for reading.  This is
     * equivalent to
     * {@link #Message(byte[],int,int,int) Message(buf, 0, buf.length, 0)}. 
     * 
     * @param buf the bytes of the Message
     */
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

    /**
     * Return the byte stream format of this message.
     * 
     * @return the bytes of this message
     */
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
    
    /**
     * Return the current position within the byte stream (for reading or
     * writing).  This is either the number of bytes read or written so far.
     * 
     * @return current position
     */
    public int
    getPosition ()
    {
        return mPosition - mStart;
    }
    
    /**
     * Move the current position within the byte stream.
     * 
     * @param position new position
     */
    public void
    setPosition (int position)
    {
        mPosition = position + mStart;
    }
    
    /**
     * Rewind the byte stream to the beginning, effectively setting the
     * position to zero.
     */
    public void
    rewind ()
    {
        mPosition = mStart;
    }

    /**
     * Return the current length of the byte stream.
     * 
     * @return length
     */
    public int
    getLength ()
    {
        if (mLength > 0) {
            return mLength;
        }
        return mBuffer.length;
    }
    
    /**
     * Return the sequence number of this Message.  A sequence number will
     * only be set if it was specified in the constructor, which typically
     * means only for incoming Messages.
     * 
     * @return sequence number
     */
    public int
    getSequence ()
    {
        return mSequenceNumber;
    }
    
    /**
     * Write a byte to the Message.
     * 
     * @param b byte
     */
    public void
    putByte (byte b)
    {
        ensureSpace(1);
        mBuffer[mPosition++] = b;
    }
    
    public void
    putBytes (byte[] b, int off, int len)
    {
        ensureSpace(len);
        System.arraycopy(b, off, mBuffer, mPosition, len);
        mPosition += len;
    }
    
    public void
    putBytes (byte[] b)
    {
        putBytes(b, 0, b.length);
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
    putByteString (byte[] b, int offset, int length)
    {
        ensureSpace(4 + length);
        putInt(length);
        System.arraycopy(b, offset, mBuffer, mPosition, length);
        mPosition += length;
    }
    
    public void
    putByteString (byte[] b)
    {
        putByteString(b, 0, b.length);
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
        putByteString(b);
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
    
    /**
     * Given a list of encodable types, iterate the list and add each item
     * as if the appropriate <code>put*</code> call was made.  This is useful
     * if you may be receiving an arbitrary list of objects from an outside
     * source.
     * 
     * <p>If any object in the list can't be encoded, an
     * IllegalArgumentException will be thrown.  Encodable object types are:
     * <code>Byte</code>, <code>Boolean</code>, <code>Integer</code>,
     * <code>Long</code>, <code>BigInteger</code>, and <code>byte[]</code>.
     * 
     * @param l the list of objects to add to this Message
     */
    public void
    putAll (List l)
    {
        for (Iterator i = l.iterator(); i.hasNext(); ) {
            Object obj = i.next();
            if (obj instanceof String) {
                putString((String) obj);
            } else if (obj instanceof Byte) {
                putByte(((Byte) obj).byteValue());
            } else if (obj instanceof Boolean) {
                putBoolean(((Boolean) obj).booleanValue());
            } else if (obj instanceof Integer) {
                putInt(((Integer) obj).intValue());
            } else if (obj instanceof Long) {
                putInt64(((Long) obj).longValue());
            } else if (obj instanceof BigInteger) {
                putMPZ((BigInteger) obj);
            } else if (obj instanceof byte[]) {
                putByteString((byte[]) obj);
            } else {
                throw new IllegalArgumentException("Unknown encoding type: " + obj.getClass().getName());
            }
        }
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
    
    public byte[]
    getByteString ()
    {
        int len = getInt();
        byte[] b = new byte[len];
        ensureSpace(len);
        System.arraycopy(mBuffer, mPosition, b, 0, len);
        mPosition += len;
        return b;
    }
    
    public String
    getString ()
    {
        byte[] b = getByteString();
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
     * @param encrypting true if this packet will be encrypted (used for
     *     optimizing the use of entropy)
     */
    /* package */ void
    packetize (CraiRandom random, int blockSize, boolean encrypting)
    {
        // pad up at least 4 bytes, to nearest block-size (usually 8)
        int padding = 3 + blockSize - ((mPosition - mStart + 8) % blockSize);
        byte[] pad = new byte[padding];
        if (encrypting) {
            // leave the padding as zero bytes unless we're encrypting
            random.getBytes(pad);
        }

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
