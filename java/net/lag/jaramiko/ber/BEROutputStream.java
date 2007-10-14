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
        public void encode (OutputStream out, Object obj) throws IOException;
    }
    
    
    public
    BEROutputStream (OutputStream out)
    {
        mOutStream = out;
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
        encoder.encode(mOutStream, item);
    }
    
    /* package */ void
    writeTerminator ()
        throws IOException
    {
        Tag.TERMINATOR.write(mOutStream);
    }
    
    public static void
    writeContainer (OutputStream out, Tag tag, Iterable sequence)
        throws IOException
    {
        tag.write(out);
        BEROutputStream subOut = new BEROutputStream(out);
        for (Iterator iter = sequence.iterator(); iter.hasNext(); ) {
            Object item = iter.next();
            subOut.write(item);
        }
        subOut.writeTerminator();
    }
    
    /**
     * Encode an object into BER data.  This is just a convenience method.
     * 
     * @param a java object of a type with a registered codec
     * @return BER-encoded data
     * @throws IOException if there was an error encoding the object
     */
    public static byte[]
    encode (Object obj)
        throws IOException
    {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write(obj);
        return buffer.toByteArray();
    }
    
    
    private OutputStream mOutStream;
    
    private static Map sEncoderTable = new HashMap();   // class name -> Encoder
    
    static {
        CommonCodecs.register();
    }
}
