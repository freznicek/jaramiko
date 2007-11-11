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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.*;


public class BEROutputStream
{
    public static interface Encoder
    {
        public void encode (OutputStream out, Object obj, boolean useIndefiniteLength) throws IOException;
    }
    
    
    public
    BEROutputStream (OutputStream out, boolean useIndefiniteLength)
    {
        mOutStream = out;
        mUseIndefiniteLength = useIndefiniteLength;
    }
    
    public
    BEROutputStream (OutputStream out)
    {
        this(out, true);
    }
    
    public static void
    register (Class c, Encoder e)
    {
        if (c == null) {
            sEncoderTable.put("null", e);
        } else {
            sEncoderTable.put(c.getName(), e);
        }
    }
    
    private static Encoder
    getEncoder (Object obj)
    {
        if (obj == null) {
            return (Encoder) sEncoderTable.get("null");
        }
        
        Class c = obj.getClass();
        while (c != null) {
            Encoder encoder = (Encoder) sEncoderTable.get(c.getName());
            if (encoder != null) {
                return encoder;
            }

            // must check the interfaces to handle things like List.
            // java hides some interfaces in the superclass, so we have to check on each iteration.
            Class[] ifaces = c.getInterfaces();
            for (int i = 0; i < ifaces.length; i++) {
                encoder = (Encoder) sEncoderTable.get(ifaces[i].getName());
                if (encoder != null) {
                    return encoder;
                }
            }

            c = c.getSuperclass();
        }
        
        return null;
    }

    public static boolean
    canEncode (Object item)
    {
        return getEncoder(item) != null;
    }
    
    public void
    write (Object item)
        throws IOException
    {
        Encoder encoder = getEncoder(item);
        if (encoder == null) {
            throw new BERException("Can't encode object of type " + item.getClass().getName());
        }
        encoder.encode(mOutStream, item, mUseIndefiniteLength);
    }
    
    /* package */ void
    writeTerminator ()
        throws IOException
    {
        Tag.TERMINATOR.write(mOutStream);
    }
    
    public static void
    writeContainer (OutputStream out, Tag tag, Iterable sequence, boolean useIndefiniteLength)
        throws IOException
    {
        if (useIndefiniteLength) {
            tag.write(out);
            BEROutputStream subOut = new BEROutputStream(out, useIndefiniteLength);
            for (Iterator iter = sequence.iterator(); iter.hasNext(); ) {
                Object item = iter.next();
                subOut.write(item);
            }
            subOut.writeTerminator();
        } else {
            // write the contents into a buffer, then dump that buffer into the stream.
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            BEROutputStream subOut = new BEROutputStream(buffer, useIndefiniteLength);
            for (Iterator iter = sequence.iterator(); iter.hasNext(); ) {
                Object item = iter.next();
                subOut.write(item);
            }
            byte[] dump = buffer.toByteArray();
            
            tag.asSize(dump.length).write(out);
            out.write(dump);
        }
    }

    /**
     * Encode an object into BER data.  This is just a convenience method.
     * 
     * @param obj a java object of a type with a registered codec
     * @param useIndefiniteLength true if containers should be encoded as
     *     indefinite-length (the normal mode); false if containers should be
     *     buffered as they're written, to track lengths8
     * @return BER-encoded data
     * @throws IOException if there was an error encoding the object
     */
    public static byte[]
    encode (Object obj, boolean useIndefiniteLength)
        throws IOException
    {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer, useIndefiniteLength).write(obj);
        return buffer.toByteArray();
    }
    
    /**
     * Encode an object into BER data.  This is just a convenience method.
     * 
     * @param obj a java object of a type with a registered codec
     * @return BER-encoded data
     * @throws IOException if there was an error encoding the object
     */
    public static byte[]
    encode (Object obj)
        throws IOException
    {
        return encode(obj, true);
    }
    
    
    private OutputStream mOutStream;
    private boolean mUseIndefiniteLength = true;
    
    private static Map sEncoderTable = new HashMap();   // class name -> Encoder
    
    static {
        CommonCodecs.register();
    }
}
