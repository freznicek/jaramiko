/*
 * Copyright (C) 2007  Danger, Inc.
 * 3101 Park Blvd, Palo Alto CA 94306
 */

package net.lag.jaramiko.ber;

import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.*;

import net.lag.jaramiko.Util;


/**
 * Some common codecs for built-in types: null, boolean, int, long, BigInteger,
 * byte[], String, and List.
 */
/* package */ class CommonCodecs
{
    public static class BooleanCodec
        implements BEROutputStream.Encoder, BERInputStream.Decoder
    {
        public void
        encode (OutputStream out, Object obj)
            throws IOException
        {
            BOOLEAN_TYPE.asSize(1).write(out);
            if (((Boolean) obj).booleanValue()) {
                out.write(0xff);
            } else {
                out.write(0);
            }
        }
        
        public Object
        decode (InputStream in, Tag tag)
            throws IOException
        {
            if (tag.getSize() != 1) {
                throw new BERException("Unexpected size of boolean: " + tag.getSize());
            }
            if (in.read() == 0) {
                return Boolean.FALSE;
            } else {
                return Boolean.TRUE;
            }
        }
    }
    
    
    public static class IntegerCodec
        implements BEROutputStream.Encoder, BERInputStream.Decoder
    {
        public void
        encode (OutputStream out, Object obj)
            throws IOException
        {
            if (obj instanceof Integer) {
                obj = BigInteger.valueOf(((Integer) obj).intValue());
            } else if (obj instanceof Long) {
                obj = BigInteger.valueOf(((Long) obj).longValue());
            }
            byte[] buffer = ((BigInteger) obj).toByteArray();
            INTEGER_TYPE.asSize(buffer.length).write(out);
            out.write(buffer);
        }

        public Object
        decode (InputStream in, Tag tag)
            throws IOException
        {
            byte[] buffer = new byte[tag.getSize()];
            if (Util.readAll(in, buffer) < buffer.length) {
                throw new IOException("Truncated integer");
            }
            return new BigInteger(buffer);
        }
    }

    
    public static class BytesCodec
        implements BEROutputStream.Encoder, BERInputStream.Decoder
    {
        public void
        encode (OutputStream out, Object obj)
            throws IOException
        {
            byte[] buffer = (byte[]) obj;
            BYTES_TYPE.asSize(buffer.length).write(out);
            out.write(buffer);
        }

        public Object
        decode (InputStream in, Tag tag)
            throws IOException
        {
            byte[] buffer = new byte[tag.getSize()];
            if (Util.readAll(in, buffer) < buffer.length) {
                throw new IOException("Truncated byte[]");
            }
            return buffer;
        }
    }

    
    public static class NullCodec
        implements BEROutputStream.Encoder, BERInputStream.Decoder
    {
        public void
        encode (OutputStream out, Object obj)
            throws IOException
        {
            NULL_TYPE.asSize(0).write(out);
        }
        
        public Object
        decode (InputStream in, Tag tag)
        {
            return null;
        }
    }
    
    public static class StringCodec
        implements BEROutputStream.Encoder, BERInputStream.Decoder
    {
        public void
        encode (OutputStream out, Object obj)
            throws IOException
        {
            byte[] buffer = ((String) obj).getBytes("UTF-8");
            UTF8_TYPE.asSize(buffer.length).write(out);
            out.write(buffer);
        }

        public Object
        decode (InputStream in, Tag tag)
            throws IOException
        {
            byte[] buffer = new byte[tag.getSize()];
            if (Util.readAll(in, buffer) < buffer.length) {
                throw new IOException("Truncated byte[]");
            }
            return new String(buffer, "UTF-8");
        }
    }

    
    public static class ListCodec
        implements BEROutputStream.Encoder, BERInputStream.Decoder
    {
        public void
        encode (OutputStream out, Object obj)
            throws IOException
        {
            BEROutputStream.writeContainer(out, LIST_TYPE, (List) obj);
        }

        public Object
        decode (InputStream in, Tag tag)
            throws IOException
        {
            BERInputStream subIn = new BERInputStream(in);
            List ret = new ArrayList();
            while (subIn.hasNext()) {
                ret.add(subIn.next());
            }
            return ret;
        }
    }

    
    private static Tag BOOLEAN_TYPE = Tag.create(Tag.UNIVERSAL, 1);
    private static Tag INTEGER_TYPE = Tag.create(Tag.UNIVERSAL, 2);
    private static Tag BYTES_TYPE = Tag.create(Tag.UNIVERSAL, 4);
    private static Tag NULL_TYPE = Tag.create(Tag.UNIVERSAL, 5);
    private static Tag UTF8_TYPE = Tag.create(Tag.UNIVERSAL, 12);
    private static Tag LIST_TYPE = Tag.createContainer(Tag.UNIVERSAL, 16);
    
    private static volatile boolean sRegistered = false;
    
    /* package */ static void register ()
    {
        if (sRegistered) {
            return;
        }
        
        BEROutputStream.register(Boolean.class, new BooleanCodec());
        BERInputStream.register(BOOLEAN_TYPE, new BooleanCodec());

        BEROutputStream.register(Integer.class, new IntegerCodec());
        BEROutputStream.register(Long.class, new IntegerCodec());
        BEROutputStream.register(BigInteger.class, new IntegerCodec());
        BERInputStream.register(INTEGER_TYPE, new IntegerCodec());

        BEROutputStream.register(byte[].class, new BytesCodec());
        BERInputStream.register(BYTES_TYPE, new BytesCodec());

        BEROutputStream.register(null, new NullCodec());
        BERInputStream.register(NULL_TYPE, new NullCodec());

        BEROutputStream.register(String.class, new StringCodec());
        BERInputStream.register(UTF8_TYPE, new StringCodec());

        BEROutputStream.register(List.class, new ListCodec());
        BERInputStream.register(LIST_TYPE, new ListCodec());
        
        sRegistered = true;
    }
}
