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
 * Created on May 23, 2005
 */

package net.lag.paramiko;

import java.io.IOException;
import java.math.BigInteger;

/**
 * @author robey
 */
public class FakeTransport
    implements TransportInterface
{
    public void
    sendMessage (Message m)
    {
        mMessage = m;
    }
    
    public void
    sendUserMessage (Message m, int timeout_ms)
    {
        mUserMessage = m;
    }
    
    public void
    setKH (BigInteger k, byte[] h)
    {
        mK = k;
        mH = h;
    }
    
    public void
    saveException (IOException x)
    {
        // pass
    }
    	 
    public void
    activateOutbound ()
    {
        mActivated = true;
    }
    
    public String
    getRemoteVersion ()
    {
        return "SSH-2.0-lame";
    }
    
    public String
    getLocalVersion ()
    {
        return "SSH-2.0-paramiko_1.0";
    }
    
    public byte[]
    getRemoteKexInit ()
    {
        return "remote-kex-init".getBytes();
    }
    
    public byte[]
    getLocalKexInit ()
    {
        return "local-kex-init".getBytes();
    }
    
    public void
    verifyKey (byte[] key, byte[] sig)
    {
        mVerifyKey = key;
        mVerifySig = sig;
    }
    
    public void
    expectPacket (byte expect)
    {
        mExpect = expect;
    }
    
    public boolean
    inServerMode ()
    {
        return mServerMode;
    }
    
    public PKey
    getServerKey ()
    {
        return new FakeKey();
    }
    
    public byte[]
    getSessionID ()
    {
        return null;
    }

    public void
    registerMessageHandler (byte ptype, MessageHandler handler)
    {
        // pass
    }
    
    public void
    unlinkChannel (int chanID)
    {
        // pass
    }
    
    public void
    close ()
    {
        // pass
    }
    
    
    public Message mMessage;
    public Message mUserMessage;
    public byte mExpect;
    public BigInteger mK;
    public byte[] mH;
    public byte[] mVerifyKey;
    public byte[] mVerifySig;
    public boolean mActivated = false;
    public boolean mServerMode = false;
}
