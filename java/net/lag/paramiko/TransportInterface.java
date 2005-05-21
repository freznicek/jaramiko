/*
 * Created on May 14, 2005
 */

package net.lag.paramiko;

import java.io.IOException;
import java.math.BigInteger;

/**
 * This makes it easier to unit-test the Kex implementations, by letting the
 * Transport interface be easily stubbed out.
 * 
 * @author robey
 */
/* package */ interface TransportInterface
{
    public boolean inServerMode ();    
    public void expectPacket (byte ptype);
    public void sendMessage (Message m) throws IOException;
    public String getLocalVersion ();
    public String getRemoteVersion ();
    public byte[] getLocalKexInit ();
    public byte[] getRemoteKexInit ();
    public PKey getServerKey ();
    public void setKH (BigInteger k, byte[] h);
    public void verifyKey (byte[] hostKey, byte[] sig);
    public void activateOutbound () throws IOException;
}
