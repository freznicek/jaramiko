/*
 * Created on May 7, 2005
 */

package net.lag.paramiko;

import java.net.InetSocketAddress;
import java.net.Socket;
import junit.framework.*;


/**
 * @author robey
 */
public class WeirdNetTest
    extends TestCase
{
    public void
    testWeird ()
        throws Exception
    {
        Socket sock = new Socket();
        sock.connect(new InetSocketAddress("localhost", 22));
        
        BaseTransport t = new BaseTransport(sock);
        t.setLog(new ConsoleLog());
        //t.setDumpPackets(true);
        t.startClient(new Event());
        
        try {
            Thread.sleep(5000);
        } catch (InterruptedException x) { }
        
    }
}
