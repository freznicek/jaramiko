/*
 * Copyright (C) 2005-2007 Robey Pointer <robey@lag.net>
 *
 * This file is part of jaramiko.
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
 */

package net.lag.jaramiko;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

import junit.framework.TestCase;


public class ChannelTest
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
        mTS = new ServerTransport(mSocketS);
        mTC = new ClientTransport(mSocketC);
        //mTC.setLog(new ConsoleLog());
        //mTS.setLog(new ConsoleLog());
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

    // verify that exec_command() does something reasonable
    public void
    testExecCommand ()
        throws Exception
    {
        PKey hostKey = PKey.readPrivateKeyFromStream(new FileInputStream("test/test_rsa.key"), null);
        PKey publicHostKey = PKey.createFromBase64(hostKey.getBase64());
        mTS.addServerKey(hostKey);
        final FakeServer server = new FakeServer();
        
        final Event sync = new Event();
        new Thread(new Runnable() {
            public void run () {
                try {
                    mTS.start(server, 15000);
                    sync.set();
                } catch (IOException x) { }
            }
        }).start();
        
        mTC.start(publicHostKey, 15000);
        mTC.authPassword("slowdive", "pygmalion", 15000);
        
        sync.waitFor(5000);
        assertTrue(sync.isSet());
        assertTrue(mTS.isActive());
        
        Channel chan = mTC.openSession(5000);
        Channel schan = mTS.accept(5000);
        assertFalse(chan.execCommand("no", 5000));
        chan.close();
        schan.close();
        
        chan = mTC.openSession(5000);
        assertTrue(chan.execCommand("yes", 5000));
        schan = mTS.accept(5000);
        
        schan.getOutputStream().write("Hello there.\n".getBytes());
        schan.getStderrOutputStream().write("This is on stderr.\n".getBytes());
        schan.close();
        
        BufferedReader r = new BufferedReader(new InputStreamReader(chan.getInputStream()));
        assertEquals("Hello there.", r.readLine());
        assertEquals(null, r.readLine());
        r = new BufferedReader(new InputStreamReader(chan.getStderrInputStream()));
        assertEquals("This is on stderr.", r.readLine());
        assertEquals(null, r.readLine());
        chan.close();
        
        // now try it with combined stdout/stderr
        chan = mTC.openSession(5000);
        assertTrue(chan.execCommand("yes", 5000));
        schan = mTS.accept(5000);
        schan.getOutputStream().write("Hello there\n".getBytes());
        schan.getStderrOutputStream().write("This is on stderr.\n".getBytes());
        schan.close();
        
        chan.setCombineStderr(true);
        r = new BufferedReader(new InputStreamReader(chan.getInputStream()));
        assertEquals("Hello there", r.readLine());
        assertEquals("This is on stderr.", r.readLine());
        assertEquals(null, r.readLine());
        chan.close();
    }
    
    // verify that invoke_shell() does something reasonable
    public void
    testInvokeShell ()
        throws Exception
    {
        PKey hostKey = PKey.readPrivateKeyFromStream(new FileInputStream("test/test_rsa.key"), null);
        PKey publicHostKey = PKey.createFromBase64(hostKey.getBase64());
        mTS.addServerKey(hostKey);
        final FakeServer server = new FakeServer();
        
        final Event sync = new Event();
        new Thread(new Runnable() {
            public void run () {
                try {
                    mTS.start(server, 15000);
                    sync.set();
                } catch (IOException x) { }
            }
        }).start();
        
        mTC.start(publicHostKey, 15000);
        mTC.authPassword("slowdive", "pygmalion", 15000);
        
        sync.waitFor(5000);
        assertTrue(sync.isSet());
        assertTrue(mTS.isActive());
        
        Channel chan = mTC.openSession(5000);
        assertTrue(chan.invokeShell(5000));
        Channel schan = mTS.accept(5000);
        chan.getOutputStream().write("communist j. cat\n".getBytes());
        assertFalse(chan.isClosed());
        chan.close();
        assertTrue(chan.isClosed());
        
        BufferedReader r = new BufferedReader(new InputStreamReader(schan.getInputStream()));
        assertEquals("communist j. cat", r.readLine());
        schan.close();
    }
    
    // verify that ChannelException is thrown for a bad channel-open request
    public void
    testChannelException ()
        throws Exception
    {
        PKey hostKey = PKey.readPrivateKeyFromStream(new FileInputStream("test/test_rsa.key"), null);
        PKey publicHostKey = PKey.createFromBase64(hostKey.getBase64());
        mTS.addServerKey(hostKey);
        final FakeServer server = new FakeServer();
        
        final Event sync = new Event();
        new Thread(new Runnable() {
            public void run () {
                try {
                    mTS.start(server, 15000);
                    sync.set();
                } catch (IOException x) { }
            }
        }).start();
        
        mTC.start(publicHostKey, 15000);
        mTC.authPassword("slowdive", "pygmalion", 15000);
        
        sync.waitFor(5000);
        assertTrue(sync.isSet());
        assertTrue(mTS.isActive());

        try {
            mTC.openChannel("bogus", null, 5000);
            fail("expecting exception");
        } catch (ChannelException x) {
            assertEquals(x.getChannelError(), ChannelError.ADMINISTRATIVELY_PROHIBITED);
        }
    }
    
    // verify that getExitStatus works
    public void
    testExitStatus ()
        throws Exception
    {
        PKey hostKey = PKey.readPrivateKeyFromStream(new FileInputStream("test/test_rsa.key"), null);
        PKey publicHostKey = PKey.createFromBase64(hostKey.getBase64());
        mTS.addServerKey(hostKey);
        final FakeServer server = new FakeServer();
        
        final Event sync = new Event();
        new Thread(new Runnable() {
            public void run () {
                try {
                    mTS.start(server, 15000);
                    sync.set();
                } catch (IOException x) { }
            }
        }).start();
        
        mTC.start(publicHostKey, 15000);
        mTC.authPassword("slowdive", "pygmalion", 15000);
        
        sync.waitFor(5000);
        assertTrue(sync.isSet());
        assertTrue(mTS.isActive());

        Channel chan = mTC.openSession(5000);
        assertTrue(chan.execCommand("yes", 5000));
        Channel schan = mTS.accept(5000);
        schan.getOutputStream().write("Hello there.\n".getBytes());
        // trigger an EOF
        schan.shutdownRead();
        schan.shutdownWrite();
        schan.sendExitStatus(23);
        schan.close();
        
        BufferedReader r = new BufferedReader(new InputStreamReader(chan.getInputStream()));
        assertEquals("Hello there.", r.readLine());
        assertEquals(null, r.readLine());
        assertEquals(23, chan.getExitStatus(5000));
        chan.close();
    }
    
    // verify that we can change the window & max packet sizes
    public void
    testChangeWindowSize ()
        throws Exception
    {
        PKey hostKey = PKey.readPrivateKeyFromStream(new FileInputStream("test/test_rsa.key"), null);
        PKey publicHostKey = PKey.createFromBase64(hostKey.getBase64());
        mTS.addServerKey(hostKey);
        mTC.setWindowSize(94321);
        mTC.setMaxPacketSize(65000);
        final FakeServer server = new FakeServer();

        final Event sync = new Event();
        new Thread(new Runnable() {
            public void run () {
                try {
                    mTS.start(server, 15000);
                    sync.set();
                } catch (IOException x) { }
            }
        }).start();

        mTC.start(publicHostKey, 15000);
        mTC.authPassword("slowdive", "pygmalion", 15000);

        sync.waitFor(5000);
        assertTrue(sync.isSet());
        assertTrue(mTS.isActive());

        Channel chan = mTC.openSession(5000);
        assertTrue(chan.execCommand("yes", 5000));
        Channel schan = mTS.accept(5000);
        
        assertEquals(94321, schan.mOutWindowSize);
        assertEquals(65000, schan.mOutMaxPacketSize);

        chan.close();
        schan.close();
    }
    
    // verify that a pty request works
    public void
    testPTY ()
        throws Exception
    {
        PKey hostKey = PKey.readPrivateKeyFromStream(new FileInputStream("test/test_rsa.key"), null);
        PKey publicHostKey = PKey.createFromBase64(hostKey.getBase64());
        mTS.addServerKey(hostKey);
        final FakeServer server = new FakeServer();
        
        final Event sync = new Event();
        new Thread(new Runnable() {
            public void run () {
                try {
                    mTS.start(server, 15000);
                    sync.set();
                } catch (IOException x) { }
            }
        }).start();
        
        mTC.start(publicHostKey, 15000);
        mTC.authPassword("slowdive", "pygmalion", 15000);
        
        sync.waitFor(5000);
        assertTrue(sync.isSet());
        assertTrue(mTS.isActive());
        
        Channel chan = mTC.openSession(5000);
        TerminalModes modes = new TerminalModes();
        modes.put(TerminalModes.ECHO, 23);
        modes.put(TerminalModes.IXOFF, 900);
        assertTrue(chan.getPTY("vt100", 80, 24, modes, 5000));
        assertTrue(chan.invokeShell(5000));
        Channel schan = mTS.accept(5000);

        assertEquals("vt100", server.mPTYTerm);
        assertEquals(80, server.mPTYWidth);
        assertEquals(24, server.mPTYHeight);
        assertEquals(23, server.mPTYModes.get(TerminalModes.ECHO));
        assertEquals(900, server.mPTYModes.get(TerminalModes.IXOFF));
        assertFalse(server.mPTYModes.contains(TerminalModes.IXON));
        
        chan.getOutputStream().write("communist j. cat\n".getBytes());
        assertFalse(chan.isClosed());
        chan.close();
        assertTrue(chan.isClosed());
        
        BufferedReader r = new BufferedReader(new InputStreamReader(schan.getInputStream()));
        assertEquals("communist j. cat", r.readLine());
        schan.close();
    }
    

    private Socket mSocketC;
    private Socket mSocketS;
    private ClientTransport mTC;
    private ServerTransport mTS;
}
