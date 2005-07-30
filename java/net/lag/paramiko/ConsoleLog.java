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
 * Created on May 10, 2005
 */

package net.lag.paramiko;

import java.text.SimpleDateFormat;
import java.util.Date;


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
        System.err.println(getThreadID() + " ERR: " + text);
    }

    public void
    warning (String text)
    {
        System.err.println(getThreadID() + " WRN: " + text);
    }

    public void
    notice (String text)
    {
        System.err.println(getThreadID() + " NTC: " + text);
    }

    public void
    debug (String text)
    {
        System.err.println(getThreadID() + " DBG: " + text);
    }

    public void
    dump (String text, byte[] data, int offset, int length)
    {
        String tidstr = getThreadID();
        for (int i = 0; i < length; i += 16) {
            System.err.println(tidstr + " DMP: " + text + ": " + dumpHex(data, offset + i, length - i));
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
    
    private String
    getThreadID ()
    {
        String timestamp = sFormat.format(new Date());
        
        int tid = ((Integer) sThreadID.get()).intValue();
        String tidstr = "t" + Integer.toString(tid);
        if (tid < 10) {
            tidstr = tidstr + "  ";
        } else if (tid < 100) {
            tidstr = tidstr + " ";
        }
        return timestamp + " " + tidstr;
    }

    
    private static int sNextThreadID = 1;
    private static ThreadLocal sThreadID = new ThreadLocal() {
        protected synchronized Object initialValue () {
            synchronized (ConsoleLog.class) {
                return new Integer(sNextThreadID++);
            }
        }
    };
    
    private static SimpleDateFormat sFormat = new SimpleDateFormat("HH:mm:ss.SSS");
}
