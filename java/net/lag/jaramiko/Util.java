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
 * Created on May 13, 2005
 */

package net.lag.jaramiko;

import java.io.InputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.util.*;

import net.lag.jaramiko.ber.BERInputStream;
import net.lag.jaramiko.ber.BEROutputStream;


/**
 * Dumb little utility functions.
 */
public class Util
{
    private
    Util ()
    {
        // don't instantiate
    }
    
    /**
     * Replace non-ASCII characters in a string with either a hex quote of the
     * form <code>\\xHH</code> or (for chars above 255) a unicode quote of the
     * form <code>\\uHHHH</code>.  Existing backslashes are quoted too.  The
     * resulting string will only contain chars between 32 and 126.
     * 
     * @param s the string to quote
     * @return a string safe to print or log
     */
    public static final String
    safeString (String s)
    {
        StringBuffer out = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c < 32) || ((c > 126) && (c < 256))) {
                String hex = Integer.toHexString(c);
                while (hex.length() < 2) {
                    hex = "0" + hex;
                }
                out.append("\\x" + hex);
            } else if (c >= 256) {
                String hex = Integer.toHexString(c);
                while (hex.length() < 4) {
                    hex = "0" + hex;
                }
                out.append("\\u" + hex);
            } else if (c == '\\') {
                out.append("\\\\");
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    // replacement for String.split() in java 4.
    public static final String[]
    splitString (String orig, String delim, int max)
    {
        List out = new ArrayList();
        while (true) {
            if (out.size() == max - 1) {
                break;
            }
            int n = orig.indexOf(delim);
            if (n < 0) {
                break;
            }
            out.add(orig.substring(0, n));
            orig = orig.substring(n + delim.length());
        }
        out.add(orig);
        return (String[]) out.toArray(new String[0]);
    }

    public static final String[]
    splitString (String orig, String delim)
    {
        return splitString(orig, delim, -1);
    }

    public static final String[]
    getStackTrace (Exception x)
    {
        StringWriter sw = new StringWriter();
        x.printStackTrace(new PrintWriter(sw));
        return splitString(sw.toString(), "\n");
    }
    
    /**
     * Decode a string of hex digits into a byte array.  For example, the
     * string <code>"FF3C"</code> would be decoded into the byte array
     * <code>new byte[] { -1, 0x3c }</code>.  This is mostly just used for
     * unit tests.
     * 
     * @param s the hex string to decode
     * @return the decoded byte array
     */
    public static final byte[]
    decodeHex (String s)
    {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < s.length(); i += 2) {
            out[i/2] = (byte) Integer.parseInt(s.substring(i, i+2), 16);
        }
        return out;
    }

    public static final String
    encodeHex (byte[] x, int off, int len)
    {
        StringBuffer out = new StringBuffer();
        for (int i = 0; i < len; i++) {
            String s = Integer.toHexString((int) x[off + i] & 0xff).toUpperCase();
            if (s.length() < 2) {
                out.append('0');
            }
            out.append(s);
        }
        return out.toString();
    }
    
    public static final String
    encodeHex (byte[] x)
    {
        return encodeHex(x, 0, x.length);
    }
    
    public static final String
    join (String[] list, String glue)
    {
        StringBuffer out = new StringBuffer();
        for (int i = 0; i < list.length; i++) {
            if (i > 0) {
                out.append(glue);
            }
            out.append(list[i]);
        }
        return out.toString();
    }
    
    /**
     * Incredibly lazy method for decoding BER sequences from private key
     * files, knowing that they're always a single sequence of ints.
     * 
     * @param data a byte array to decode
     * @return an array of BigIntegers representing the key data
     */
    public static BigInteger[]
    decodeBERSequence (byte[] data)
        throws SSHException
    {
        Object obj;
        try {
            obj = BERInputStream.decode(data);
        } catch (IOException x) {
            throw new SSHException("BER decoding error: " + x);
        }
        if (!(obj instanceof List)) {
            throw new SSHException("Expected BER sequence");
        }
        List list = (List) obj;
        for (int i = 0; i < list.size(); i++) {
            if (!(list.get(i) instanceof BigInteger)) {
                throw new SSHException("Expected integer at BER sequence element " + i);
            }
        }
        BigInteger[] nums = new BigInteger[list.size()];
        list.toArray(nums);
        return nums;
    }
    
    public static byte[]
    encodeBERSequence (BigInteger[] nums)
        throws SSHException
    {
        List list = Arrays.asList(nums);
        try {
            return BEROutputStream.encode(list);
        } catch (IOException x) {
            throw new SSHException("BER encoding error: " + x);
        }
    }
    
    /**
     * Continue reading from a stream until EOF is reached, or the requested
     * number of bytes is read.
     * 
     * @param in the stream to read from
     * @param buffer the buffer to fill
     * @param off offset within the buffer to begin reading into
     * @param len number of bytes to read
     * @return number of bytes actually read (will only be less than the
     *     requested number at EOF)
     * @throws IOException if an IOException occurred while reading from
     *     the stream
     */
    public static int
    readAll (InputStream in, byte[] buffer, int off, int len)
        throws IOException
    {
        int soFar = 0;
        while (soFar < len) {
            int n = in.read(buffer, off + soFar, len - soFar);
            if (n < 0) {
                return soFar;
            }
            soFar += n;
        }
        return len;
    }
    
    public static int
    readAll (InputStream in, byte[] buffer)
        throws IOException
    {
        return readAll(in, buffer, 0, buffer.length);
    }
}
