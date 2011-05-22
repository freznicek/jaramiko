/*
 * Copyright (C) 2007 Robert J Colquhoun <Robert.Colquhoun@gmail.com>
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

package net.lag.jaramiko;

import java.util.*;


/**
 * A map of pseudo-terminal modes to configured values, as sent by the client
 * when requesting a pty over a {@link Channel}. These map key bindings to
 * events, among other arcana.
 *
 * The constants are from RFC 4254 Section 8:
 * <a href="http://www.ietf.org/rfc/rfc4254.txt">http://www.ietf.org/rfc/rfc4254.txt</a>
 */
public class TerminalModes
{
    public
    TerminalModes ()
    {
        mParams = new HashMap();
    }

    /**
     * Retrieve one of the values set by the client. If no value was defined
     * for this key, 0 is returned.
     *
     * @param key one of the constants (like <code>VINTR</code>) defined by
     *     RFC 4254
     * @return the value, or 0
     */
    public int
    get (int key)
    {
        Integer value = (Integer) mParams.get(Integer.valueOf(key));
        if (value == null) {
            return 0;
        }
        return value.intValue();
    }

    /**
     * Return true if the requested key was defined by the client in its pty
     * request.
     *
     * @param key one of the constants (like <code>VINTR</code> defined by
     *     RFC 4254
     * @return true if the value was defined by the client; false if not
     */
    public boolean
    contains (int key)
    {
        return mParams.containsKey(Integer.valueOf(key));
    }

    /**
     * Set a pty request parameter.
     *
     * @param key one of the constants (like <code>VINTR</code> defined by
     *     RFC 4254
     * @param value the value of this parameter
     */
    public void
    put (int key, int value)
    {
        mParams.put(Integer.valueOf(key), Integer.valueOf(value));
    }

    /* package */ static TerminalModes
    fromBytes (byte[] data)
    {
        TerminalModes modes = new TerminalModes();
        Message m = new Message(data);
        while (m.getPosition() < m.getLength()) {
            int key = (int) m.getByte();
            if ((key == 0) || (key > 159)) {
                break;
            }
            int value = m.getInt();
            modes.put(key, value);
        }
        return modes;
    }

    /* package */ byte[]
    toBytes ()
    {
        Message m = new Message();
        for (Iterator iter = mParams.keySet().iterator(); iter.hasNext(); ) {
            int key = ((Integer) iter.next()).intValue();
            int value = ((Integer) mParams.get(Integer.valueOf(key))).intValue();
            m.putByte((byte) key);
            m.putInt(value);
        }
        m.putByte((byte) 0);
        return m.toByteArray();
    }


    private Map mParams;    // Map<Integer, Integer>

    public static final int TTY_OP_END = 0;
    public static final int VINTR = 1;
    public static final int VQUIT = 2;
    public static final int VERASE = 3;
    public static final int VKILL = 4;
    public static final int VEOF = 5;
    public static final int VEOL = 6;
    public static final int VEOL2 = 7;
    public static final int VSTART = 8;
    public static final int VSTOP = 9;
    public static final int VSUSP = 10;
    public static final int VDSUSP = 11;
    public static final int VREPRINT = 12;
    public static final int VWERASE = 13;
    public static final int VLNEXT = 14;
    public static final int VFLUSH = 15;
    public static final int VSWTCH = 16;
    public static final int VSTATUS = 17;
    public static final int VDISCARD = 18;

    public static final int IGNPAR = 30;
    public static final int PARMRK = 31;
    public static final int INPCK = 32;
    public static final int ISTRIP = 33;
    public static final int INLCR = 34;
    public static final int IGNCR = 35;
    public static final int ICRNL = 36;
    public static final int IUCLC = 37;
    public static final int IXON = 38;
    public static final int IXANY = 39;
    public static final int IXOFF = 40;
    public static final int IMAXBEL = 41;

    public static final int ISIG = 50;
    public static final int ICANON = 51;
    public static final int XCASE = 52;
    public static final int ECHO = 53;
    public static final int ECHOE = 54;
    public static final int ECHOK = 55;
    public static final int ECHONL = 56;
    public static final int NOFLSH = 57;
    public static final int TOSTOP = 58;
    public static final int IEXTEN = 59;
    public static final int ECHOCTL = 60;
    public static final int ECHOKE = 61;
    public static final int PENDIN = 62;

    public static final int OPOST = 70;
    public static final int OLCUC = 71;
    public static final int ONLCR = 72;
    public static final int OCRNL = 73;
    public static final int ONOCR = 74;
    public static final int ONLRET = 75;

    public static final int CS7 = 90;
    public static final int CS8 = 91;
    public static final int PARENB = 92;
    public static final int PARODD = 93;

    public static final int TTY_OP_ISPEED = 128;
    public static final int TTY_OP_OSPEED = 129;
}
