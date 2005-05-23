/*
 * Created on May 23, 2005
 */

package net.lag.paramiko;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author robey
 */
public class FakeKey
    extends PKey
{
    public Message
    signSSHData (SecureRandom random, byte[] data)
    {
        Message m = new Message();
        m.putBytes("fake-sig".getBytes());
        return m;
    }
    
    public boolean
    verifySSHSignature (byte[] data, Message sig)
    {
        return false;
    }
    
    protected void
    buildFromBER (BigInteger[] ints)
    {
        // pass
    }
    
    protected void
    buildFromMessage (Message m)
    {
        // pass
    }
    
    public byte[]
    toByteArray ()
    {
        return "fake-key".getBytes();
    }
    
    public boolean
    canSign ()
    {
        return true;
    }
    
    public int
    getBits ()
    {
        return 0;
    }
    
    public String
    getSSHName ()
    {
        return "none";
    }
}
