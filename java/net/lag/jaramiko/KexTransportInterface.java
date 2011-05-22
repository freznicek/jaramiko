/*
 * Copyright (C) 2005-2007 Robey Pointer <robey@lag.net>
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

import java.io.IOException;
import java.math.BigInteger;


/**
 * This makes it easier to unit-test the Kex implementations, by letting the
 * Transport interface be easily stubbed out.
 */
/* package */ interface KexTransportInterface
{
    public String getLocalVersion ();
    public String getRemoteVersion ();
    public byte[] getLocalKexInit ();
    public byte[] getRemoteKexInit ();

    public void registerMessageHandler (byte ptype, MessageHandler handler);
    public void expectPacket (byte ptype);
    public void expectPacket (byte ptype1, byte ptype2);
    public void sendMessage (Message m) throws IOException;

    public LogSink getLog ();
    public PKey getServerKey ();
    public void verifyKey (byte[] hostKey, byte[] sig) throws SSHException;
    public void setKH (BigInteger k, byte[] h);
    public void kexComplete () throws IOException;
}
