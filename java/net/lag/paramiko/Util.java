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

}
