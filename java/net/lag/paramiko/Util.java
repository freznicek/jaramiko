/*
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

}
