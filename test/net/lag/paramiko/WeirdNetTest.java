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
        sock.connect(new InetSocketAddress("localhost", 2200));
        
        BaseTransport t = new BaseTransport(sock);
        t.setLog(new ConsoleLog());
        t.setDumpPackets(true);
        Event e = new Event();
        t.startClient(e);
        
        System.err.println("waiting for event...");
        e.waitFor(10000);
        if (! e.isSet()) {
            System.err.println("never set. :(");
        } else {
            System.err.println("OK, connected!");
            t.authPassword("robey", "foo");
        }
        
    }
}
