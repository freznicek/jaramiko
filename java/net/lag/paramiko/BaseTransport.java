/*
 * Created on May 11, 2005
 */

package net.lag.paramiko;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

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
        mInKex = false;
        mClearToSend = new Event();
        mLog = new NullLog();
        
        mSocket = socket;
        mInStream = mSocket.getInputStream();
        mOutStream = mSocket.getOutputStream();
        mRandom = new SecureRandom();
        
        // FIXME: set timeout on mInStream
        mPacketizer = new Packetizer(mInStream, mOutStream, mRandom);
        mExpectedPacket = 0;
        
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
    
    /**
     * Return true if this SSH session is operating in server mode; false if
     * operating in client mode.
     * 
     * @return true if this SSH session is operating in server mode
     */
    public boolean
    inServerMode ()
    {
        return mServerMode;
    }
    
    
    // -----  package
    
    
    /* package */ void
    expectPacket (byte ptype)
    {
        mExpectedPacket = ptype;
    }

    /* package */ void
    sendMessage (Message m)
        throws IOException
    {
        mPacketizer.write(m);
        if (mPacketizer.needRekey() && ! mInKex) {
            sendKexInit();
        }
    }
    
    /* package */ final String
    getLocalVersion ()
    {
        return mLocalVersion;
    }
    
    /* package */ final String
    getRemoteVersion ()
    {
        return mRemoteVersion;
    }
    
    /* package */ final byte[]
    getLocalKexInit ()
    {
        return mLocalKexInit;
    }

    /* package */ final byte[]
    getRemoteKexInit ()
    {
        return mRemoteKexInit;
    }
    
    /* package */ final void
    setKH (BigInteger k, byte[] h)
    {
        mK = k;
        mH = h;
        if (mSessionID == null) {
            mSessionID = h;
        }
    }
    
    /* package */ final void
    verifyKey (byte[] hostKey, byte[] sig)
    {
        // FIXME
    }
    
    // switch on newly negotiated encryption parameters for outbound traffic
    /* package */ final void
    activateOutbound ()
        throws IOException
    {
        Message m = new Message();
        m.putByte(MessageType.NEW_KEYS);
        sendMessage(m);
        // FIXME
    }

    
    // -----  private
    
    
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
        mInKex = true;
        sendMessage(m);
    }
    
    // return the first string from clientPrefs that's in serverPrefs
    private String
    filter (List clientPrefs, List serverPrefs)
    {
        for (Iterator i = clientPrefs.iterator(); i.hasNext(); ) {
            String c = (String) i.next();
            if (serverPrefs.contains(c)) {
                return c;
            }
        }
        return null;
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
            
            while (mActive) {
                if (mPacketizer.needRekey() && ! mInKex) {
                    sendKexInit();
                }
                Message m = mPacketizer.read();
                byte ptype = m.getByte();
                switch (ptype) {
                case MessageType.IGNORE:
                    continue;
                case MessageType.DISCONNECT:
                    parseDisconnect(m);
                    mActive = false;
                    mPacketizer.close();
                    break;
                case MessageType.DEBUG:
                    parseDebug(m);
                    continue;
                }
                
                if (mExpectedPacket != 0) {
                    if (ptype != mExpectedPacket) {
                        throw new SSHException("Expecting packet " + MessageType.getDescription(mExpectedPacket) +
                                               ", got " + MessageType.getDescription(ptype));
                    }
                    mExpectedPacket = 0;
                    if ((ptype >= 30) && (ptype <= 39)) {
                        mKexEngine.parseNext(ptype, m);
                        continue;
                    }
                }
                
                if (! parsePacket(ptype, m)) {
                    mLog.warning("Oops, unhandled packet type " + MessageType.getDescription(ptype));
                    Message resp = new Message();
                    resp.putByte(MessageType.UNIMPLEMENTED);
                    resp.putInt(m.getSequence());
                    sendMessage(resp);
                }
            }
        } catch (SSHException x) {
            mLog.error("Exception: " + x);
            logStackTrace(x);
        } catch (IOException x) {
            mLog.error("I/O exception in transport thread: " + x);
        }
        
        // FIXME
        // for chan in self.channels.values(): chan.unlink()
        if (mActive) {
            mActive = false;
            mPacketizer.close();
            if (mCompletionEvent != null) {
                mCompletionEvent.set();
            }
            //if (mAuthEvent != null) {
             //   mAuthEvent.set();
           // }
            // for event in self.cahnnel_events.values(): event.set()
        }
        try {
            mSocket.close();
        } catch (IOException x) { }
    }
    
    private boolean
    parsePacket (byte ptype, Message m)
        throws IOException
    {
        switch (ptype) {
        case MessageType.NEW_KEYS:
            parseNewKeys();
            break;
        case MessageType.GLOBAL_REQUEST:
            //parseGlobalRequest(m);
            break;
        case MessageType.REQUEST_SUCCESS:
            //parseRequestSuccess(m);
            break;
        case MessageType.REQUEST_FAILURE:
            //parseRequestFailure(m);
            break;
        // FIXME...
        case MessageType.KEX_INIT:
            parseKexInit(m);
            break;
        }
        return false;
    }
    
    private void
    parseDisconnect (Message m)
    {
        int code = m.getInt();
        String desc = m.getString();
        mLog.notice("Disconnect (code " + code + "): " + desc);
    }
    
    private void
    parseDebug (Message m)
    {
        boolean alwaysDisplay = m.getBoolean();
        String text = m.getString();
        String lang = m.getString();
        mLog.debug("Debug msg: " + Util.safeString(text));
    }
    
    private void
    parseNewKeys ()
    {
        mLog.debug("Switch to new keys...");
        //activateInbound();
        // FIXME...
    }
    
    private void
    parseKexInit (Message m)
        throws IOException
    {
        // okay, no sending requests until kex init is done
        mClearToSend.clear();
        if (mLocalKexInit == null) {
            // send ours too
            sendKexInit();
        }
        
        // there's no way to avoid this being a huge function, so here goes:
        byte[] cookie = m.getBytes(16);
        List kexAlgorithmList = m.getList();
        List serverKeyAlgorithmList = m.getList();
        List clientEncryptAlgorithmList = m.getList();
        List serverEncryptAlgorithmList = m.getList();
        List clientMacAlgorithmList = m.getList();
        List serverMacAlgorithmList = m.getList();
        List clientCompressAlgorithmList = m.getList();
        List serverCompressAlgorithmList = m.getList();
        List clientLangList = m.getList();
        List serverLangList = m.getList();
        boolean kexFollows = m.getBoolean();
        int unused = m.getInt();
        
        // no compression support (yet?)
        List supportedCompressions = Arrays.asList(new String[] { "none" });
        if ((filter(supportedCompressions, clientCompressAlgorithmList) == null) ||
            (filter(supportedCompressions, serverCompressAlgorithmList) == null)) {
            throw new SSHException("Incompatible SSH peer");
        }
        mAgreedKex = mServerMode ? filter(kexAlgorithmList, Arrays.asList(mPreferredKex)) :
            filter(Arrays.asList(mPreferredKex), kexAlgorithmList);
        if (mAgreedKex == null) {
            throw new SSHException("Incompatible SSH peer (no acceptable kex algorithm)");
        }
        // FIXME: in server mode, remember to filter out keys that we don't actually have on hand 
        mAgreedServerKey = mServerMode ? filter(serverKeyAlgorithmList, Arrays.asList(mPreferredKeys)) :
            filter(Arrays.asList(mPreferredKeys), serverKeyAlgorithmList);
        if (mAgreedServerKey == null) {
            throw new SSHException("Incompatible SSH peer (no acceptable host key)");
        }

        if (mServerMode) {
            mAgreedLocalCipher = filter(serverEncryptAlgorithmList, Arrays.asList(mPreferredCiphers));
            mAgreedRemoteCipher = filter(clientEncryptAlgorithmList, Arrays.asList(mPreferredCiphers));
        } else {
            mAgreedLocalCipher = filter(Arrays.asList(mPreferredCiphers), clientEncryptAlgorithmList);
            mAgreedRemoteCipher = filter(Arrays.asList(mPreferredCiphers), serverEncryptAlgorithmList);
        }
        if ((mAgreedLocalCipher == null) || (mAgreedRemoteCipher == null)) {
            throw new SSHException("Incompatible SSH peer (no acceptable ciphers)");
        }
        mLog.debug("Ciphers agreed: local=" + mAgreedLocalCipher + ", remote=" + mAgreedRemoteCipher);
        
        if (mServerMode) {
            mAgreedLocalMac = filter(serverMacAlgorithmList, Arrays.asList(mPreferredMacs));
            mAgreedRemoteMac = filter(clientMacAlgorithmList, Arrays.asList(mPreferredMacs));
        } else {
            mAgreedLocalMac = filter(Arrays.asList(mPreferredMacs), clientMacAlgorithmList);
            mAgreedRemoteMac = filter(Arrays.asList(mPreferredMacs), serverMacAlgorithmList);
        }
        if ((mAgreedLocalMac == null) || (mAgreedRemoteMac == null)) {
            throw new SSHException("Incompatible SSH peer (no accpetable macs)");
        }

        mLog.debug("using kex " + mAgreedKex + "; server key type " + mAgreedServerKey + "; cipher: local " +
                   mAgreedLocalCipher + ", remote " + mAgreedRemoteCipher + "; mac: local " + mAgreedLocalMac +
                   ", remote " + mAgreedRemoteMac);
        
        // save for computing hash later...
        /* now wait!  openssh has a bug (and others might too) where there are
         * actually some extra bytes (one NUL byte in openssh's case) added to
         * the end of the packet but not parsed.  turns out we need to throw
         * away those bytes because they aren't part of the hash.
         */
        byte[] data = m.toByteArray();
        mRemoteKexInit = new byte[m.getPosition() + 1];
        mRemoteKexInit[0] = MessageType.KEX_INIT;
        System.arraycopy(data, 0, mRemoteKexInit, 1, m.getPosition());
        
        // FIXME start kex
    }
    
    private void
    logStackTrace (Exception x)
    {
        String[] s = Util.getStackTrace(x);
        for (int i = 0; i < s.length; i++) {
            mLog.debug(s[i]);
        }
    }
    
    
    // ahhh java...  weird hoops to implement an interface only within this package
    private class BaseTransportInterface
        implements TransportInterface
    {
        public boolean inServerMode () { return BaseTransport.this.inServerMode(); }  
        public void expectPacket (byte ptype) { BaseTransport.this.expectPacket(ptype); }
        public void sendMessage (Message m) throws IOException { BaseTransport.this.sendMessage(m); }
        public String getLocalVersion () { return BaseTransport.this.getLocalVersion(); }
        public String getRemoteVersion () { return BaseTransport.this.getRemoteVersion(); }
        public byte[] getLocalKexInit () { return BaseTransport.this.getLocalKexInit(); }
        public byte[] getRemoteKexInit () { return BaseTransport.this.getRemoteKexInit(); }
        public void setKH (BigInteger k, byte[] h) { BaseTransport.this.setKH(k, h); }
        public void verifyKey (byte[] hostKey, byte[] sig) { BaseTransport.this.verifyKey(hostKey, sig); }
        public void activateOutbound () throws IOException { BaseTransport.this.activateOutbound(); }
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
    protected Kex mKexEngine;
    
    // negotiation:
    protected String mAgreedKex;
    protected String mAgreedServerKey;
    protected String mAgreedLocalCipher;
    protected String mAgreedRemoteCipher;
    protected String mAgreedLocalMac;
    protected String mAgreedRemoteMac;
    
    // transport state:
    protected String mLocalVersion;
    protected String mRemoteVersion;
    protected byte[] mLocalKexInit;
    protected byte[] mRemoteKexInit;
    protected byte mExpectedPacket;
    private boolean mInKex;
    private byte[] mSessionID;
    private BigInteger mK;
    private byte[] mH;
    
    protected boolean mActive;
    protected boolean mServerMode;
    protected Event mCompletionEvent;
    protected Event mClearToSend;
    protected LogSink mLog;
}
