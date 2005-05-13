/*
 * Created on May 11, 2005
 */

package net.lag.paramiko;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @author robey
 */
public class BaseTransport
{
    public
    BaseTransport (Socket socket)
        throws IOException
    {
        mActive = false;
        mServerMode = false;
        mClearToSend = new Event();
        mLog = new NullLog();
        
        mSocket = socket;
        mInStream = mSocket.getInputStream();
        mOutStream = mSocket.getOutputStream();
        mRandom = new SecureRandom();
        
        // FIXME: set timeout on mInStream
        mPacketizer = new Packetizer(mInStream, mOutStream, mRandom);
        
        mLocalVersion = "SSH-" + PROTO_ID + "-" + CLIENT_ID;
        mRemoteVersion = null;
    }
    
    public void
    setLog (LogSink logger)
    {
        mLog = logger;
    }
    
    public void
    startClient (Event e)
    {
        e.clear();
        mCompletionEvent = e;
        mServerMode = false;
        mActive = true;
        new Thread(new Runnable() {
            public void run () {
                privateRun();
            }
        }).start();
    }
    
    
    // -----  private
    
    
    private void
    sendMessage (Message m)
        throws IOException
    {
        mPacketizer.write(m);
        if (mPacketizer.needRekey()) {
            sendKexInit();
        }
    }
    
    private void
    checkBanner ()
        throws IOException
    {
        String line = null;
        
        for (int i = 0; i < 5; i++) {
            // give them 5 seconds for the first line, then just 2 seconds each additional line
            try {
                if (i == 0) {
                    mSocket.setSoTimeout(5000);
                } else {
                    mSocket.setSoTimeout(2000);
                }
            } catch (SocketException x) {
                // hrm.
                throw new IOException("Unable to set socket timeout");
            }
            line = mPacketizer.readline();
            if (line == null) {
                throw new SSHException("Error reading SSH protocol banner");
            }
            if (line.startsWith("SSH-")) {
                break;
            }
            mLog.debug("Banner: " + line);
        }
        
        if (! line.startsWith("SSH-")) {
            throw new SSHException("Indecipherable protocol version '" + line + "'");
        }
        mRemoteVersion = line;
        
        // pull off any attached comment
        int i = line.indexOf(' ');
        if (i > 0) {
            line = line.substring(0, i);
        }
        String[] segs = line.split("\\-", 3);
        if (segs.length < 3) {
            throw new SSHException("Invalid SSH banner");
        }
        String version = segs[1];
        String client = segs[2];
        if (! version.equals("1.99") && ! version.equals("2.0")) {
            throw new SSHException("Incompatible version (" + version + " instead of 2.0)");
        }
        mLog.notice("Connected (version " + version + ", client " + client + ")");
        try {
            mSocket.setSoTimeout(0);
        } catch (SocketException x) { }
    }
    
    private void
    sendKexInit ()
        throws IOException
    {
        mClearToSend.clear();
        String[] availableServerKeys = mPreferredKeys;
        if (mServerMode) {
            // FIXME check for modulus pack
        }
        
        byte[] rand = new byte[16];
        mRandom.nextBytes(rand);

        Message m = new Message();
        m.putByte(MessageType.KEX_INIT);
        m.putBytes(rand);
        m.putList(Arrays.asList(mPreferredKex));
        m.putList(Arrays.asList(availableServerKeys));
        m.putList(Arrays.asList(mPreferredCiphers));
        m.putList(Arrays.asList(mPreferredCiphers));
        m.putList(Arrays.asList(mPreferredMacs));
        m.putList(Arrays.asList(mPreferredMacs));
        m.putString("none");
        m.putString("none");
        m.putString("");
        m.putString("");
        m.putBoolean(false);
        m.putInt(0);
        
        // save a copy for later
        mLocalKexInit = m.toByteArray();
        sendMessage(m);
    }
    
    private void
    privateRun ()
    {
        if (mServerMode) {
            mLog.debug("starting thread (server mode): " + Integer.toHexString(this.hashCode()));
        } else {
            mLog.debug("starting thread (client mode): " + Integer.toHexString(this.hashCode()));
        }
        
        try {
            mPacketizer.writeline(mLocalVersion + "\r\n");
            checkBanner();
            sendKexInit();
            mExpectedPacket = MessageType.KEX_INIT;
        } catch (Exception x) {
            // FIXME
        }
    }
    
    private static final String PROTO_ID = "2.0";
    private static final String CLIENT_ID = "paramikoj_0.1";
    
    private String[] mPreferredCiphers = { "aes128-cbc", "blowfish-cbc", "aes256-cbc", "3des-cbc" };
    private String[] mPreferredMacs = { "hmac-sha1", "hmac-md5", "hmac-sha1-96", "hmac-md5-96" };
    private String[] mPreferredKeys = { "ssh-rsa", "ssh-dss" };
    private String[] mPreferredKex = { "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1" };
    
    protected Socket mSocket;
    protected InputStream mInStream;
    protected OutputStream mOutStream;
    protected SecureRandom mRandom;
    protected Packetizer mPacketizer;
    
    // transport state:
    protected String mLocalVersion;
    protected String mRemoteVersion;
    protected byte[] mLocalKexInit;
    protected int mExpectedPacket;
    
    protected boolean mActive;
    protected boolean mServerMode;
    protected Event mCompletionEvent;
    protected Event mClearToSend;
    protected LogSink mLog;
}
