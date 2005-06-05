/*
 * Created on May 31, 2005
 */

package net.lag.paramiko;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import junit.framework.TestCase;

/**
 * @author robey
 */
public class TransportTest
    extends TestCase
{
    private static Socket[]
    makeSocketPair ()
        throws IOException
    {
        ServerSocket serv = new ServerSocket();
        serv.bind(new InetSocketAddress(InetAddress.getByName("localhost"), 0));

        Socket client = new Socket();
        client.connect(new InetSocketAddress(InetAddress.getByName("localhost"), serv.getLocalPort()));
        
        Socket client2 = serv.accept();
        return new Socket[] { client2, client };
    }
    
    // verify that the key generation algorithm works
    public void
    testComputeKey ()
        throws Exception
    {
        Socket[] pair = makeSocketPair();
        BaseTransport t = new BaseTransport(pair[0]);
        t.setKH(K, H);
        byte[] key = t.computeKey((byte)'C', 16);
        assertEquals("207E66594CA87C44ECCBA3B3CD39FDDB", Util.encodeHex(key));
    }

    private static final BigInteger K =
        new BigInteger("12328109597968658152337725611420972077453906897310" +
                       "13308727636229713994294810725197135362927727095072" +
                       "96759612401802191955568143056534122385270077606457" +
                       "72155346973065923356933935614008528405243669748075" +
                       "95105196728487437944334601131189868168266248652911" +
                       "16513647975790797391795651716378444844877749505443" +
                       "714557929");
    private static final byte[] H =
        Util.decodeHex("0C8307CDE6856FF30BA93684EB0F04C2520E9ED3");
}
