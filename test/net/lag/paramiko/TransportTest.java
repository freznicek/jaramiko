/*
 * Created on May 31, 2005
 */

package net.lag.paramiko;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
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
    
    public void
    setUp ()
        throws Exception
    {
        Socket[] pair = makeSocketPair();
        mSocketS = pair[0];
        mSocketC = pair[1];
        mTS = new Transport(mSocketS);
        mTC = new Transport(mSocketC);
    }
    
    public void
    tearDown ()
        throws Exception
    {
        mTC.close();
        mTS.close();
        mSocketC.close();
        mSocketS.close();
    }
    
    // verify that the security options can be modified
    public void
    testSecurityOptions ()
        throws IOException
    {
        SecurityOptions o = mTC.getSecurityOptions();
        
        List ciphers = o.getCiphers();
        assertTrue(ciphers.size() > 2);
        ciphers.clear();
        ciphers.add("aes256-cbc");
        ciphers.add("blowfish-cbc");
        o.setCiphers(ciphers);
        
        List c2 = o.getCiphers();
        assertEquals(2, c2.size());
        assertEquals("aes256-cbc", (String) c2.get(0));
        assertEquals("blowfish-cbc", (String) c2.get(1));
        
        try {
            ciphers.clear();
            ciphers.add("aes256-cbc");
            ciphers.add("made-up-cipher");
            o.setCiphers(ciphers);
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException x) {
            // pass
        }
    }

    // verify that the key generation algorithm works
    public void
    testComputeKey ()
        throws Exception
    {
        mTC.setKH(K, H);
        byte[] key = mTC.computeKey((byte)'C', 16);
        assertEquals("207E66594CA87C44ECCBA3B3CD39FDDB", Util.encodeHex(key));
    }
    
    /*
     * verify that we can establish an ssh link with ourselves across the
     * loopback sockets.  this is hardly "simple" but it's simpler than the
     * later tests. :)
     */
    public void
    testSimple ()
        throws Exception
    {
        PKey hostKey = PKey.readPrivateKeyFromStream(new FileInputStream("test/test_rsa.key"), null);
        PKey publicHostKey = PKey.createFromBase64(hostKey.getBase64());
        mTS.addServerKey(hostKey);
        final FakeServer server = new FakeServer();
        assertEquals(null, mTC.getUsername());
        assertEquals(null, mTS.getUsername());
        assertFalse(mTC.isAuthenticated());
        assertFalse(mTS.isAuthenticated());
        
        final Event sync = new Event();
        new Thread(new Runnable() {
            public void run () {
                try {
                    mTS.startServer(server, 15000);
                    sync.set();
                } catch (IOException x) { }
            }
        }).start();
        mTC.startClient(publicHostKey, 15000);
        mTC.authPassword("slowdive", "pygmalion", 15000);
        sync.waitFor(5000);
        
        assertTrue(sync.isSet());
        assertTrue(mTS.isActive());
        assertEquals("slowdive", mTC.getUsername());
        assertEquals("slowdive", mTS.getUsername());
        assertTrue(mTC.isAuthenticated());
        assertTrue(mTS.isAuthenticated());
    }
    

    private Socket mSocketC;
    private Socket mSocketS;
    private Transport mTC;
    private Transport mTS;

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
