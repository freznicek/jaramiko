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
import java.util.*;


public class ArtificialSequence
{
    public
    ArtificialSequence (Iterable list)
    {
        mList = new ArrayList();
        if (list != null) {
            for (Iterator iter = list.iterator(); iter.hasNext(); ) {
                mList.add(iter.next());
            }
        }
    }
    
    public boolean
    equals (Object obj)
    {
        if (obj == this) {
            return true;
        }
        if (! (obj instanceof ArtificialSequence)) {
            return false;
        }
        return ((ArtificialSequence) obj).mList.equals(mList);
    }

    
    public List mList;
    
    private static Tag TAG = Tag.createContainer(Tag.APPLICATION, 200);


    private static class Encoder
        implements BEROutputStream.Encoder
    {
        public void
        encode (OutputStream out, Object obj)
            throws IOException
        {
            BEROutputStream.writeContainer(out, TAG, ((ArtificialSequence) obj).mList);
        }
    }
    
    
    private static class Decoder
        implements BERInputStream.Decoder
    {
        public Object
        decode (InputStream in, Tag tag)
            throws IOException
        {
            return new ArtificialSequence(BERInputStream.decodeContainer(in));
        }
    }


    static {
        BEROutputStream.register(ArtificialSequence.class, new Encoder());
        BERInputStream.register(TAG, new Decoder());
    }
}
