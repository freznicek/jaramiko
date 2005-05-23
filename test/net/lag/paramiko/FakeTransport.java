/*
 * Created on May 23, 2005
 */

package net.lag.paramiko;

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
    setKH (BigInteger k, byte[] h)
    {
        mK = k;
        mH = h;
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
    
    
    public Message mMessage;
    public byte mExpect;
    public BigInteger mK;
    public byte[] mH;
    public byte[] mVerifyKey;
    public byte[] mVerifySig;
    public boolean mActivated = false;
    public boolean mServerMode = false;
}
