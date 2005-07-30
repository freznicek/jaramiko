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

package net.lag.paramiko;

import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * Dumb little utility functions.
 * 
 * @author robey
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
    
    public static final String[]
    getStackTrace (Exception x)
    {
        StringWriter sw = new StringWriter();
        x.printStackTrace(new PrintWriter(sw));
        return sw.toString().split("\n");
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
}
