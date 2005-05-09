/*
 * Created on May 7, 2005
 */

package net.lag.paramiko;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
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
        ServerSocketChannel serv = ServerSocketChannel.open();
        serv.socket().bind(new InetSocketAddress(9999));
        
        SocketChannel sock = SocketChannel.open(new InetSocketAddress("127.0.0.1", 9999));
        
        System.err.println("-> begin");

        ByteBuffer buf = ByteBuffer.allocate(1);
        sock.socket().setSoTimeout(2000);
        sock.read(buf);
    }
}
