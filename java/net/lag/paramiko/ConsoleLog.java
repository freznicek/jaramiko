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
 * Created on May 10, 2005
 */

package net.lag.paramiko;


/**
 * Simple {@link LogSink} implementation which dumps paramiko's log messages
 * to java's <code>System.err</code>.  The log level is indicated with a
 * three-letter abbreviation, but no timestamp or other info is provided.
 * 
 * @author robey
 */
public class ConsoleLog
    implements LogSink
{
    public void
    error (String text)
    {
        System.err.println("ERR: " + text);
    }

    public void
    warning (String text)
    {
        System.err.println("WRN: " + text);
    }

    public void
    notice (String text)
    {
        System.err.println("NTC: " + text);
    }

    public void
    debug (String text)
    {
        System.err.println("DBG: " + text);
    }

    public void
    dump (String text, byte[] data, int offset, int length)
    {
        for (int i = 0; i < length; i += 16) {
            System.err.println("DMP: " + text + ": " + dumpHex(data, offset + i, length - i));
        }
    }
    
    private String
    dumpHex (byte[] data, int offset, int length)
    {
        StringBuffer hex = new StringBuffer();
        StringBuffer ascii = new StringBuffer();
        
        for (int i = 0; i < 16; i++) {
            if (i >= length) {
                hex.append("   ");
                ascii.append(' ');
            } else {
                byte b = data[offset + i];
                String x = Integer.toHexString((int)b & 0xff).toUpperCase();
                if (x.length() < 2) {
                    hex.append('0');
                }
                hex.append(x);
                hex.append(' ');

                if ((b > 32) && (b < 127)) {
                    ascii.append((char)b);
                } else {
                    ascii.append('.');
                }
            }
        }
        
        return hex.toString() + "   " + ascii.toString();
    }

}
