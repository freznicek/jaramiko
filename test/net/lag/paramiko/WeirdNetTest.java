/*
 * Created on May 7, 2005
 */

package net.lag.paramiko;

import java.io.FileInputStream;
import java.io.InputStream;
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
        if (true) return;
        
        Socket sock = new Socket();
        sock.connect(new InetSocketAddress("tavi.lag.net", 22));
        
        Transport t = new Transport(sock);
        t.setLog(new ConsoleLog());
        t.setDumpPackets(true);
        PKey key = PKey.readPrivateKeyFromStream(new FileInputStream("/Users/robey/.ssh/id_rsa"), null);
        t.startClient(PKey.createFromBase64(TAVI_HOST_KEY), 5000);
        t.authPrivateKey("robey", key, 5000);
        Channel c = t.openChannel("session", null, 5000);
        assertTrue(c != null);
        assertTrue(c.getPTY("vt100", 80, 24, 5000));
        assertTrue(c.invokeShell(5000));
        
        InputStream is = c.getInputStream();
        c.setTimeout(5000);
        c.getOutputStream().write("echo hello\n".getBytes());
        while (true) {
            byte[] b = new byte[1024];
            int n = is.read(b);
            System.err.print(new String(b, 0, n));
        }
    }
    
    private static String TAVI_HOST_KEY =
        "AAAAB3NzaC1yc2EAAAABIwAAAIEArLCLIphyfl3JDa34i7nQB5DYRa7v3kMFWtgGf8A" +
        "EsQj/LVg+iRFi5pXitFeroz1H0sRnLGGI1rKBC0oxc+y8j/CXPR0B09Ch3sWjTFE2No" +
        "KMOuhO2IOghLOp6dzdw3TBlaqNXj4q8qokjE9b3y2r1l+73NWsXPrkGqS5RlqoXGk=";
}
