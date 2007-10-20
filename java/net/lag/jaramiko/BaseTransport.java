/*
 * Copyright (C) 2005-2006 Robey Pointer <robey@lag.net>
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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.io.InterruptedIOException;
import java.io.PrintWriter;
import java.io.StringWriter;
//import java.net.SocketTimeoutException;
import java.util.*;

import net.lag.crai.*;


/**
 * Common transport implementation shared by ClientTransport and
 * ServerTransport.
 */
/* package */ abstract class BaseTransport
    implements Transport
{
    /**
     * Create a new SSH session over an existing socket.  This only
     * initializes the Transport object; it doesn't begin negotiating the
     * SSH ession yet.  Use {@link #startClient} to begin a client session,
     * or {@link #startServer} to begin a server session.
     * 
     * @param socket the (previously connected) socket to use for this session 
     * @throws IOException if there's an error fetching the input/output
     *     streams from the socket
     */
    public
    BaseTransport (Socket socket)
        throws IOException
    {
        if (sCrai == null) {
            try {
                sCrai = (Crai) Class.forName("net.lag.craijce.CraiJCE").newInstance();
            } catch (Throwable t) {
                throw new RuntimeException("Unable to load default CraiJCE: " + t);
            }
        }
        mActive = false;
        mInKex = false;
        mClearToSend = new Event();
        mLog = new NullLog();
        
        mSocket = socket;
        mInStream = mSocket.getInputStream();
        mOutStream = mSocket.getOutputStream();
        mSecurityOptions = new SecurityOptions(KNOWN_CIPHERS, KNOWN_MACS, KNOWN_KEYS, KNOWN_KEX, KNOWN_COMPRESSIONS);
        mSecurityOptions.setCompressions(Arrays.asList(new String[] { "none" }));
        
        mChannels = new Channel[16];
        mChannelEvents = new Event[16];
        
        mSocket.setSoTimeout(100);
        mPacketizer = new Packetizer(mInStream, mOutStream, sCrai.getPRNG());
        mExpectedPacket = 0;
        mInitialKexDone = false;
        
        mLocalVersion = "SSH-" + PROTO_ID + "-" + CLIENT_ID;
        mRemoteVersion = null;
        
        mMessageHandlers = new HashMap();
        mChannelFactoryMap = new HashMap();
        mChannelFactoryMap.put("session", new Channel.Factory());
    }
    
    public void
    setLog (LogSink logger)
    {
        mLog = logger;
        mPacketizer.setLog(logger);
    }
    
    public void
    setDumpPackets (boolean dump)
    {
        mPacketizer.setDumpPackets(dump);
    }

    /**
     * Set the timeout for receiving the SSH banner from the remote server.
     * By default, this library will wait 15 seconds for a banner, to account
     * for high-latency links. You may make this timeout shorter or longer,
     * if you call this method before starting the transport.
     * 
     * @param seconds number of seconds to wait for the SSH banner when
     *     initiating handshaking
     */
    public void
    setBannerTimeout (int seconds)
    {
        mInitialBannerTimeout = seconds * 1000;
    }
    
    /**
     * Set the window size to be used on new channels. This is the amount of
     * un-acked data that can be in transit at once, so for high-latency
     * links, larger values may be better. This will also affect the size
     * of retransmit buffers.
     * 
     * @param size window size (in bytes) to use for new channels
     */
    public void
    setWindowSize (int size)
    {
        mWindowSize = size;
    }
    
    /**
     * Return the current window size used for new channels.
     * {@see #setWindowSize(int)}
     * 
     * @return window size (in bytes) being used for new channels
     */
    public int
    getWindowSize ()
    {
        return mWindowSize;
    }
    
    /**
     * Set the size of the largest SSH packet we will send. By default, we
     * will use the largest packet size allowed by the protocol spec, but some
     * servers will allow larger sizes. Use this with care: some servers will
     * disconnect if they receive a packet that's "too large". You usually
     * won't need to change this.
     * 
     * @param size the new maximum packet size, in bytes
     */
    public void
    setMaxPacketSize (int size)
    {
        mMaxPacketSize = size;
    }
    
    /**
     * Return the current maximum packet size for the SSH protocol.
     * {@see #setMaxPacketSize(int)}
     * 
     * @return the maximum packet size, in bytes
     */
    public int
    getMaxPacketSize ()
    {
        return mMaxPacketSize;
    }
    
    public SecurityOptions
    getSecurityOptions ()
    {
        return mSecurityOptions;
    }

    public boolean
    isAuthenticated ()
    {
        return mActive && (mAuthHandler != null) && mAuthHandler.isAuthenticated();
    }
    
    public String
    getUsername ()
    {
        if (! mActive || (mAuthHandler == null)) {
            return null;
        }
        return mAuthHandler.getUsername();
    }
    
    public void
    setKeepAlive (int interval_ms)
    {
        mPacketizer.setKeepAlive(interval_ms, new KeepAliveHandler () {
            public void keepAliveEvent () {
                try {
                    sendGlobalRequest("keepalive@lag.net", null, -1);
                } catch (IOException x) {
                    // pass
                }
            }
        });
    }
    
    /**
     * Turn on/off compression.  This will only have an affect before starting
     * the transport.  By default, compression is off since it negatively
     * affects interactive sessions.
     *
     * @param compress true to ask the remote client/server to compress
     *     trafic; false to refuse compression
     */
    public void
    useCompression (boolean compress)
    {
        if (compress) {
            mSecurityOptions.setCompressions(Arrays.asList(KNOWN_COMPRESSIONS));
        } else {
            mSecurityOptions.setCompressions(Arrays.asList(new String[] { "none" }));
        }
    }            

    public void
    renegotiateKeys (int timeout_ms)
        throws IOException
    {
        mCompletionEvent = new Event();
        sendKexInit();
        if (! waitForEvent(mCompletionEvent, timeout_ms)) {
            // timeout
            close();
            throw new SSHException("Timeout during key renegotiation.");
        }
    }
    
    public void
    sendIgnore (int bytes, int timeout_ms)
        throws IOException
    {
        Message m = new Message();
        m.putByte(MessageType.IGNORE);
        if (bytes <= 0) {
            byte[] b = new byte[1];
            sCrai.getPRNG().getBytes(b);
            bytes = (b[0] % 32) + 10;
        }
        byte[] data = new byte[bytes];
        sCrai.getPRNG().getBytes(data);
        m.putBytes(data);
        sendUserMessage(m, timeout_ms);
    }
    
    public Message
    sendGlobalRequest (String requestName, List parameters, int timeout_ms)
        throws IOException
    {
        if (timeout_ms > 0) {
            mCompletionEvent = new Event();
        }
        Message m = new Message();
        m.putByte(MessageType.GLOBAL_REQUEST);
        m.putString(requestName);
        m.putBoolean(timeout_ms > 0);
        if (parameters != null) {
            m.putAll(parameters);
        }
        mLog.debug("Sending global request '" + requestName + "'");
        sendUserMessage(m, timeout_ms);
        if (timeout_ms <= 0) {
            return null;
        }
        if (! waitForEvent(mCompletionEvent, timeout_ms)) {
            return null;
        }
        return mGlobalResponse;
    }
    
    public void
    close ()
    {
        Channel[] chans;
        
        synchronized (mLock) {
            mActive = false;
            mPacketizer.close();
            chans = mChannels;
            mChannels = new Channel[16];
        }
        
        for (int i = 0; i < chans.length; i++) {
            if (chans[i] != null) {
                chans[i].unlink();
            }
        }
    }
        
    
    // -----  package
    
    
    /* package */ void
    registerMessageHandler (byte ptype, MessageHandler handler)
    {
        mMessageHandlers.put(new Byte(ptype), handler);
    }
    
    /* package */ void
    expectPacket (byte ptype)
    {
        mExpectedPacket = ptype;
    }

    /* package */ void
    saveException (IOException x)
    {
        synchronized (mLock) {
            mSavedException = x;
        }
    }
    
    /* package */ IOException
    getException ()
    {
        synchronized (mLock) {
            IOException x = mSavedException;
            mSavedException = null;
            return x;
        }
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
    
    /* package */ final void
    setKH (BigInteger k, byte[] h)
    {
        mK = k;
        mH = h;
        if (mSessionID == null) {
            mSessionID = h;
        }
    }
    
    /* Compute SSH2-style key bytes, using an "id" ('A' - 'F') and a pile of
     * state common to this session.
     */
    /* package */ final byte[]
    computeKey (byte id, int nbytes)
    {
        byte[] out = new byte[nbytes];
        int sofar = 0;
        CraiDigest sha = sCrai.makeSHA1();
        
        while (sofar < nbytes) {
            Message m = new Message();
            m.putMPZ(mK);
            m.putBytes(mH);
            if (sofar == 0) {
                m.putByte(id);
                m.putBytes(mSessionID);
            } else {
                m.putBytes(out, 0, sofar);
            }
            sha.reset();
            byte[] d = m.toByteArray();
            sha.update(d, 0, d.length);
            byte[] digest = sha.finish();
            if (sofar + digest.length > nbytes) {
                System.arraycopy(digest, 0, out, sofar, nbytes - sofar);
                sofar = nbytes;
            } else {
                System.arraycopy(digest, 0, out, sofar, digest.length);
                sofar += digest.length;
            }
        }
        return out;
    }
    
    private void
    startInboundCompression ()
    {
        mLog.debug("Switching on inbound compression ...");

        Class compressClass = (Class) BaseTransport.sCompressMap.get(mDescription.mRemoteCompression);
        if (compressClass != null) {
            try {
                Compressor compress = (Compressor) compressClass.newInstance();
                mPacketizer.setInboundCompressor(compress);
            } catch (Exception x) {
                throw new RuntimeException("Internal java error: " + x);
            }
        }
    }
    
    private void
    startOutboundCompression ()
    {
        mLog.debug("Switching on outbound compression ...");

        Class compressClass = (Class) BaseTransport.sCompressMap.get(mDescription.mLocalCompression);
        if (compressClass != null) {
            try {
                Compressor compress = (Compressor) compressClass.newInstance();
                mPacketizer.setOutboundCompressor(compress);
            } catch (Exception x) {
                throw new RuntimeException("Internal java error: " + x);
            }
        }
    }
    
    // ClientTransport & ServerTransport override to set the correct keys
    /* package */ void
    activateInbound ()
        throws SSHException
    {
        CipherDescription desc = mDescription.mRemoteCipher;
        MacDescription mdesc = mDescription.mRemoteMac;
        activateInbound(desc, mdesc);

        if ((mDescription.mRemoteCompression != null) &&
            (! mDescription.mRemoteCompression.equals("zlib@openssh.com") || isAuthenticated())) {
            startInboundCompression();
        }
    }
    
    /* package */ abstract void activateInbound (CipherDescription desc, MacDescription mdesc) throws SSHException;
    
    // switch on newly negotiated encryption parameters for outbound traffic
    /* package */ final void
    activateOutbound ()
        throws IOException
    {
        Message m = new Message();
        m.putByte(MessageType.NEW_KEYS);
        sendMessage(m);
        
        CipherDescription desc = mDescription.mLocalCipher;
        MacDescription mdesc = mDescription.mLocalMac;
        activateOutbound(desc, mdesc);

        if ((mDescription.mLocalCompression != null) &&
            (! mDescription.mLocalCompression.equals("zlib@openssh.com") || isAuthenticated())) {
            startOutboundCompression();
        }

        if (! mPacketizer.needRekey()) {
            mInKex = false;
        }
        // we always expect to receive NEW_KEYS now
        mExpectedPacket = MessageType.NEW_KEYS;
    }
    
    /* package */ abstract void activateOutbound (CipherDescription desc, MacDescription mdesc) throws SSHException;
    
    /* package */ void
    authTrigger ()
    {
        // delayed initiation of compression
        if ((mDescription.mLocalCompression != null) && mDescription.mLocalCompression.equals("zlib@openssh.com")) {
            startOutboundCompression();
        }
        if ((mDescription.mRemoteCompression != null) && mDescription.mRemoteCompression.equals("zlib@openssh.com")) {
            startInboundCompression();
        }
    }
    
    /**
     * Send a message, but if we're in key (re)negotation, block until that's
     * finished.  This is used for user-initiated requests.
     * 
     * @param m the message to send
     * @param timeout_ms maximum time (in milliseconds) to wait for the
     *     key exchange to finish, if it's ongoing
     * @throws IOException if there's an I/O exception on the socket
     */
    /* package */ void
    sendUserMessage (Message m, int timeout_ms)
        throws IOException
    {
        while (true) {
            synchronized (mClearToSend) {
                if (mClearToSend.isSet()) {
                    sendMessage(m);
                    return;
                }
            }
            if (! waitForEvent(mClearToSend, timeout_ms)) {
                return;
            }
        }
    }
    
    /* package */ boolean
    isActive ()
    {
        return mActive;
    }
    
    /* package */ static Crai
    getCrai ()
    {
        return sCrai;
    }
    
    /* package */ byte[] 
    getSessionID ()
    {
        return mSessionID;
    }

    
    // -----  private
    
    
    private void
    checkBanner ()
        throws IOException
    {
        String line = null;
        
        for (int i = 0; i < 5; i++) {
            /* give them 15 seconds for the first line, then just 5 seconds
             * each additional line. (some links have very high latency.) 
             */ 
            int timeout = BANNER_TIMEOUT;
            if (i == 0) {
                timeout = mInitialBannerTimeout;
            }
            try {
                line = mPacketizer.readline(timeout);
            } catch (InterruptedIOException x) {
                throw new SSHException("Timeout waiting for SSH protocol banner");
            }
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
        String[] segs = Util.splitString(line, "-", 3);
        if (segs.length < 3) {
            throw new SSHException("Invalid SSH banner");
        }
        String version = segs[1];
        String client = segs[2];
        if (! version.equals("1.99") && ! version.equals("2.0")) {
            throw new SSHException("Incompatible version (" + version + " instead of 2.0)");
        }
        mLog.notice("Connected (version " + version + ", client " + client + ")");
    }
    
    private void
    sendKexInit ()
        throws IOException
    {
        sendKexInitHook();
        
        synchronized (mClearToSend) {
            mClearToSend.clear();
        }
        
        byte[] rand = new byte[16];
        sCrai.getPRNG().getBytes(rand);

        Message m = new Message();
        m.putByte(MessageType.KEX_INIT);
        m.putBytes(rand);
        m.putList(mSecurityOptions.getKex());
        m.putList(mSecurityOptions.getKeys());
        m.putList(mSecurityOptions.getCiphers());
        m.putList(mSecurityOptions.getCiphers());
        m.putList(mSecurityOptions.getDigests());
        m.putList(mSecurityOptions.getDigests());
        m.putList(mSecurityOptions.getCompressions());
        m.putList(mSecurityOptions.getCompressions());
        m.putString("");
        m.putString("");
        m.putBoolean(false);
        m.putInt(0);
        
        // save a copy for later
        mLocalKexInit = m.toByteArray();
        mInKex = true;
        sendMessage(m);
    }
    
    /* package */ void
    sendKexInitHook ()
    {
        // pass
    }
    
    // return the first string from localPrefs that's in remotePrefs
    // (server mode overrides this to reverse the sense)
    /* package */ String
    filter (List localPrefs, List remotePrefs)
    {
        for (Iterator i = localPrefs.iterator(); i.hasNext(); ) {
            String c = (String) i.next();
            if (remotePrefs.contains(c)) {
                return c;
            }
        }
        return null;
    }
    
    /**
     * Wait for an event to trigger, up to an optional timeout.  If the
     * transport goes inactive (dead), it will return prematurely within the
     * next tenth of a second.
     * It will also return prematurely if the thread is interrupted.
     *  
     * @param e the event to wait on
     * @param timeout_ms maximum time to wait (in milliseconds); -1 to wait
     *     forever
     * @return true if the event was triggered; false if the timeout occurred
     *     or the thread was interrupted
     * @throws IOException if the transport disconnected while waiting
     */
    /* package */ boolean
    waitForEvent (Event e, int timeout_ms)
        throws IOException
    {
        long deadline = System.currentTimeMillis() + timeout_ms;
        while (! e.isSet()) {
            try {
                int span = (timeout_ms >= 0) ? (int)(deadline - System.currentTimeMillis()) : 100;
                if (span < 0) {
                    return false;
                }
                if (span > 100) {
                    span = 100;
                }
                if (span > 0) {
                    e.waitFor(span);
                }
            } catch (InterruptedException x) {
                // just remember it
                Thread.currentThread().interrupt();
                return false;
            }

            if (! mActive) {
                IOException x = getException();
                if (x == null) {
                    x = new SSHException("Transport closed.");
                }
                throw x;
            }
        }
        return true;
    }
    
    /* package */ void
    transportRun0 ()
    {
        try {
            mPacketizer.writeline(mLocalVersion + "\r\n");
            checkBanner();
            sendKexInit();
            mExpectedPacket = MessageType.KEX_INIT;
            
            while (mActive) {
                if (mPacketizer.needRekey() && ! mInKex) {
                    sendKexInit();
                }
                Message m = null;
                try {
                    m = mPacketizer.read();
                } catch (NeedRekeyException x) {
                    continue;
                }
                if (m == null) {
                    break;
                }
                
                byte ptype = m.getByte();
                switch (ptype) {
                case MessageType.IGNORE:
                    continue;
                case MessageType.DISCONNECT:
                    parseDisconnect(m);
                    mActive = false;
                    mPacketizer.close();
                    continue;
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
            saveException(x);
        } catch (IOException x) {
            mLog.error("I/O exception in feeder thread: " + x);
            saveException(x);
        }
        
        for (int i = 0; i < mChannels.length; i++) {
            if (mChannels[i] != null) {
                mChannels[i].unlink();
            }
        }

        if (mActive) {
            mActive = false;
            mPacketizer.close();
            if (mCompletionEvent != null) {
                mCompletionEvent.set();
            }
            
            if (mAuthHandler != null) {
                mAuthHandler.abort();
            }
            
            for (int i = 0; i < mChannelEvents.length; i++) {
                if (mChannelEvents[i] != null) {
                    mChannelEvents[i].set();
                }
            }
        }
        try {
            mSocket.close();
        } catch (IOException x) { }
    }

    /* package */ void
    transportRun ()
    {
        try {
            transportRun0();
        } catch (Throwable t) {
            mLog.error("Exception from feeder thread! " + t);
            StringWriter buffer = new StringWriter();
            t.printStackTrace(new PrintWriter(buffer));
            mLog.debug(buffer.toString());
        } finally {
            mLog.debug("Feeder thread terminating.");
        }
    }

    private boolean
    parsePacket (byte ptype, Message m)
        throws IOException
    {
        MessageHandler handler = (MessageHandler) mMessageHandlers.get(new Byte(ptype));
        if (handler != null) {
            return handler.handleMessage(ptype, m);
        }
        
        if ((ptype >= MessageType.CHANNEL_WINDOW_ADJUST) && (ptype <= MessageType.CHANNEL_FAILURE)) {
            int chanID = m.getInt();
            Channel c = null;
            if (chanID < mChannels.length) {
                c = mChannels[chanID];
            }
            if (c != null) {
                return c.handleMessage(ptype, m);
            } else {
                mLog.error("Channel request for unknown channel " + chanID);
                throw new SSHException("Channel request for unknown channel");
            }
        }
        
        switch (ptype) {
        case MessageType.NEW_KEYS:
            parseNewKeys();
            return true;
        case MessageType.GLOBAL_REQUEST:
            parseGlobalRequest(m);
            return true;
        case MessageType.REQUEST_SUCCESS:
            parseRequestSuccess(m);
            return true;
        case MessageType.REQUEST_FAILURE:
            parseRequestFailure(m);
            return true;
        case MessageType.CHANNEL_OPEN_SUCCESS:
            parseChannelOpenSuccess(m);
            return true;
        case MessageType.CHANNEL_OPEN_FAILURE:
            parseChannelOpenFailure(m);
            return true;
        case MessageType.CHANNEL_OPEN:
            parseChannelOpen(m);
            return true;
        case MessageType.KEX_INIT:
            parseKexInit(m);
            return true;
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
        m.getBoolean(); // always display?
        String text = m.getString();
        //String lang = m.getString();
        mLog.debug("Debug msg: " + Util.safeString(text));
    }
    
    private void
    parseNewKeys ()
        throws SSHException
    {
        mLog.debug("Switch to new keys...");
        activateInbound();
        
        // can also free a bunch of state here
        mLocalKexInit = null;
        mRemoteKexInit = null;
        mKexEngine = null;
        mK = null;
        
        // give ServerTransport a chance to set up an AuthHandler hook:
        parseNewKeysHook();

        if (! mInitialKexDone) {
            // this was the first key exchange
            mInitialKexDone = true;
        }
        if (mCompletionEvent != null) {
            mCompletionEvent.set();
        }
        // it's now okay to send data again (if this was a re-key)
        if (! mPacketizer.needRekey()) {
            mInKex = false;
        }
        synchronized (mClearToSend) {
            mClearToSend.set();
        }
    }
    
    /* package */ void
    parseNewKeysHook ()
    {
        // pass
    }
    
    private void
    parseGlobalRequest (Message m)
        throws IOException
    {
        String kind = m.getString();
        boolean wantReply = m.getBoolean();
        mLog.debug("Received global request '" + kind + "'");

        List response = checkGlobalRequest(kind, m);
        if (wantReply) {
            Message mx = new Message();
            if (response != null) {
                mx.putByte(MessageType.REQUEST_SUCCESS);
                mx.putAll(response);
            } else {
                mx.putByte(MessageType.REQUEST_FAILURE);
            }
            sendMessage(mx);
        }
    }
    
    /* package */ List
    checkGlobalRequest (String kind, Message m)
    {
        // ServerTransport will override this
        return null;
    }
    
    /* package */ void
    kexInitHook ()
        throws SSHException
    {
        // pass
    }
    
    /* package */ abstract KexTransportInterface createKexTransportInterface ();
    
    private void
    parseKexInit (Message m)
        throws IOException
    {
        // okay, no sending requests until kex init is done
        synchronized (mClearToSend) {
            mClearToSend.clear();
        }
        if (mLocalKexInit == null) {
            // send ours too
            sendKexInit();
        }
        
        // there's no way to avoid this being a huge function, so here goes:
        m.getBytes(16);     // cookie
        List kexAlgorithmList = m.getList();
        List serverKeyAlgorithmList = m.getList();
        List clientEncryptAlgorithmList = m.getList();
        List serverEncryptAlgorithmList = m.getList();
        List clientMacAlgorithmList = m.getList();
        List serverMacAlgorithmList = m.getList();
        List clientCompressAlgorithmList = m.getList();
        List serverCompressAlgorithmList = m.getList();
        m.getList();        // client lang list
        m.getList();        // server lang list
        m.getBoolean();     // kex follows
        m.getInt();         // unused
    
        String agreedLocalCompression = filter(mSecurityOptions.getCompressions(), clientCompressAlgorithmList);
        String agreedRemoteCompression = filter(mSecurityOptions.getCompressions(), serverCompressAlgorithmList);
        if ((agreedLocalCompression == null) || (agreedRemoteCompression == null)) {
            throw new SSHException("Incompatible SSH peer (no acceptable compression)");
        }

        String agreedKex = filter(mSecurityOptions.getKex(), kexAlgorithmList);
        if (agreedKex == null) {
            throw new SSHException("Incompatible SSH peer (no acceptable kex algorithm)");
        }
        String agreedServerKey = filter(mSecurityOptions.getKeys(), serverKeyAlgorithmList);
        if (agreedServerKey == null) {
            throw new SSHException("Incompatible SSH peer (no acceptable host key)");
        }

        String agreedLocalCipher = filter(mSecurityOptions.getCiphers(), clientEncryptAlgorithmList);
        String agreedRemoteCipher = filter(mSecurityOptions.getCiphers(), serverEncryptAlgorithmList);
        if ((agreedLocalCipher == null) || (agreedRemoteCipher == null)) {
            throw new SSHException("Incompatible SSH peer (no acceptable ciphers)");
        }
        
        String agreedLocalMac = filter(mSecurityOptions.getDigests(), clientMacAlgorithmList);
        String agreedRemoteMac = filter(mSecurityOptions.getDigests(), serverMacAlgorithmList);
        if ((agreedLocalMac == null) || (agreedRemoteMac == null)) {
            throw new SSHException("Incompatible SSH peer (no accpetable macs)");
        }

        TransportDescription d = mDescription = new TransportDescription();
        d.mKexName = agreedKex;
        d.mServerKeyType = agreedServerKey;
        d.mLocalCipherName = agreedLocalCipher;
        d.mLocalCipher = (CipherDescription) sCipherMap.get(agreedLocalCipher);
        d.mRemoteCipherName = agreedRemoteCipher;
        d.mRemoteCipher = (CipherDescription) sCipherMap.get(agreedRemoteCipher);
        d.mLocalMacAlgorithm = agreedLocalMac;
        d.mLocalMac = (MacDescription) sMacMap.get(agreedLocalMac);
        d.mRemoteMacAlgorithm = agreedRemoteMac;
        d.mRemoteMac = (MacDescription) sMacMap.get(agreedRemoteMac);
        d.mLocalCompression = agreedLocalCompression;
        d.mRemoteCompression = agreedRemoteCompression;

        kexInitHook();
        mLog.debug(d.toString());
        
        // save for computing hash later...
        /* now wait!  openssh has a bug (and others might too) where there are
         * actually some extra bytes (one NUL byte in openssh's case) added to
         * the end of the packet but not parsed.  turns out we need to throw
         * away those bytes because they aren't part of the hash.
         */
        byte[] data = m.toByteArray();
        mRemoteKexInit = new byte[m.getPosition()];
        System.arraycopy(data, 0, mRemoteKexInit, 0, m.getPosition());
        
        Class kexClass = (Class) sKexMap.get(agreedKex);
        if (kexClass == null) {
            throw new SSHException("Oops!  Negotiated kex " + agreedKex + " which I don't implement");
        }
        try {
            mKexEngine = (Kex) kexClass.newInstance();
        } catch (Exception x) {
            throw new SSHException("Internal java error: " + x);
        }
        mKexEngine.startKex(createKexTransportInterface(), sCrai);
    }
    
    private void
    parseRequestSuccess (Message m)
        throws IOException
    {
        mLog.debug("Global request successful.");
        mGlobalResponse = m;
        if (mCompletionEvent != null) {
            mCompletionEvent.set();
        }
    }        
    
    private void
    parseRequestFailure (Message m)
        throws IOException
    {
        mLog.debug("Global request denied.");
        mGlobalResponse = null;
        if (mCompletionEvent != null) {
            mCompletionEvent.set();
        }
    }

    private void
    parseChannelOpenSuccess (Message m)
    {
        int chanID = m.getInt();
        int serverChanID = m.getInt();
        int serverWindowSize = m.getInt();
        int serverMaxPacketSize = m.getInt();
        
        synchronized (mLock) {
            Channel c = mChannels[chanID];
            if (c == null) {
                mLog.warning("Success for unrequested channel! [??]");
                return;
            }
            c.setRemoteChannel(serverChanID, serverWindowSize, serverMaxPacketSize);
            mLog.notice("Secsh channel " + chanID + " opened.");
            if (mChannelEvents[chanID] != null) {
                mChannelEvents[chanID].set();
                mChannelEvents[chanID] = null;
            }
        }
    }
    
    private void
    parseChannelOpenFailure (Message m)
    {
        int chanID = m.getInt();
        int reason = m.getInt();
        String reasonStr = m.getString();
        m.getString();      // lang
        String reasonText = ChannelError.getDescription(reason);
        mLog.notice("Secsh channel " + chanID + " open FAILED: " + reasonStr + ": " + reasonText);
        
        synchronized (mLock) {
            saveException(new ChannelException(reason));
            mChannels[chanID] = null;
            if (mChannelEvents[chanID] != null) {
                mChannelEvents[chanID].set();
                mChannelEvents[chanID] = null;
            }
        }
    }
    
    /* package */ abstract void parseChannelOpen (Message m) throws IOException;
    
    public void 
    registerChannelKind (String kind, ChannelFactory factory)
    {
        mChannelFactoryMap.put(kind, factory);
    }
    
    /* package */ Channel
    getChannelForKind (int chanid, String kind, Message params)
    {
        ChannelFactory factory = (ChannelFactory) mChannelFactoryMap.get(kind);
        // If we don't know what channel factory to use, use the default Channel
        if (factory == null) {
            mLog.notice("Cannot find a ChannelFactory for the channel kind '" + kind + "'; using default Channel");
            factory = new Channel.Factory();
        }
        return factory.createChannel(kind, chanid, params);
    }  

    /* package */ Channel
    getChannelForKind (int chanid, String kind, List params)
    {
        ChannelFactory factory = (ChannelFactory) mChannelFactoryMap.get(kind);
        // If we don't know what channel factory to use, use the default Channel
        if (factory == null) {
            mLog.notice("Cannot find a ChannelFactory for the channel kind '" + kind + "'; using default Channel");
            factory = new Channel.Factory();
        }
        return factory.createChannel(kind, chanid, params);
    }
    
    // you are already holding mLock
    /* package */ int
    getNextChannel ()
    {
        for (int i = 0; i < mChannels.length; i++) {
            if (mChannels[i] == null) {
                return i;
            }
        }
        
        // expand mChannels
        int old = mChannels.length;
        Channel[] nc = new Channel[old * 2];
        System.arraycopy(mChannels, 0, nc, 0, old);
        mChannels = nc;
        Event[] ne = new Event[old * 2];
        System.arraycopy(mChannelEvents, 0, ne, 0, old);
        mChannelEvents = ne;
        
        return old;
    }
    
    private void
    logStackTrace (Exception x)
    {
        String[] s = Util.getStackTrace(x);
        for (int i = 0; i < s.length; i++) {
            mLog.debug(s[i]);
        }
    }
    
    /*
     * try to generate each of the ciphers in sCipherMap, and remove the ones
     * that throw exceptions.  different JVMs may have implement different
     * subsets.  also, many versions of java (including the sun JVM!) are
     * crippled and can't use 256-bit ciphers.  amazing.
     */
    /* package */ void
    detectUnsupportedCiphers ()
    {
        if (sCheckedCiphers) {
            return;
        }
        
        boolean giveAdvice = false;
        
        synchronized (BaseTransport.class) {
            for (Iterator i = sCipherMap.entrySet().iterator(); i.hasNext(); ) {
                Map.Entry entry = (Map.Entry) i.next();
                String name = (String) entry.getKey();
                CipherDescription desc = (CipherDescription) entry.getValue();
                try {
                    CraiCipher cipher = sCrai.getCipher(desc.mAlgorithm);
                    cipher.initEncrypt(new byte[desc.mKeySize], new byte[desc.mBlockSize]);
                } catch (CraiException x) {
                    mLog.notice("Turning off unsupported encryption: " + name);
                    if (desc.mKeySize > 16) {
                        giveAdvice = true;
                    }
                    i.remove();
                }
            }
            
            sCheckedCiphers = true;
        }
        
        if (giveAdvice) {        
            mLog.notice("Your java installation lacks support for 256-bit encryption.  " +
                        "This is due to a poor choice of defaults in Sun's java.  To fix it, " +
                        "visit: <http://java.sun.com/j2se/1.4.2/download.html> and download " +
                        "the \"unlimited strength\" files at the bottom of the page, under " +
                        "\"other downloads\".");
        }
    }

        
    private static final String PROTO_ID = "2.0";
    private static final String CLIENT_ID = "jaramiko_0.1";
    
    private static final int BANNER_TIMEOUT = 5000;
    private static final int DEFAULT_WINDOW_SIZE = 384 * 1024;
    private static final int DEFAULT_MAX_PACKET_SIZE = 34816;
    
    private static Map sCipherMap = new HashMap();
    private static Map sMacMap = new HashMap();
    private static Map sKeyMap = new HashMap();
    private static Map sKexMap = new HashMap();
    private static Map sCompressMap = new HashMap();
    private static volatile boolean sCheckedCiphers = false;
    
    // crypto abstraction (not everyone has JCE)
    /* package */ static Crai sCrai = null;
    
    static {
        // mappings from SSH protocol names to java implementation details
        sCipherMap.put("aes128-cbc", new CipherDescription(CraiCipherAlgorithm.AES_CBC, 16, 16));
        sCipherMap.put("blowfish-cbc", new CipherDescription(CraiCipherAlgorithm.BLOWFISH_CBC, 16, 8));
        sCipherMap.put("aes256-cbc", new CipherDescription(CraiCipherAlgorithm.AES_CBC, 32, 16));
        sCipherMap.put("3des-cbc", new CipherDescription(CraiCipherAlgorithm.DES3_CBC, 24, 8));

        sMacMap.put("hmac-sha1", new MacDescription("SHA1", 20, 20));
        sMacMap.put("hmac-sha1-96", new MacDescription("SHA1", 12, 20));
        sMacMap.put("hmac-md5", new MacDescription("MD5", 16, 16));
        sMacMap.put("hmac-md5-96", new MacDescription("MD5", 12, 16));
        
        sKeyMap.put("ssh-rsa", RSAKey.class);
        sKeyMap.put("ssh-dss", DSSKey.class);
        
        sKexMap.put("diffie-hellman-group1-sha1", KexGroup1.class);
        
        sCompressMap.put("zlib", ZlibCompressor.class);
        sCompressMap.put("zlib@openssh.com", ZlibCompressor.class);
    }
    
    private final String[] KNOWN_CIPHERS = { "aes128-cbc", "blowfish-cbc", "aes256-cbc", "3des-cbc" };
    private final String[] KNOWN_MACS = { "hmac-sha1", "hmac-md5", "hmac-sha1-96", "hmac-md5-96" };
    private final String[] KNOWN_KEYS = { "ssh-rsa", "ssh-dss" };
    private final String[] KNOWN_KEX = { "diffie-hellman-group1-sha1" };
    private final String[] KNOWN_COMPRESSIONS = { "zlib@openssh.com", "zlib", "none" };

    /* zlib@openssh.com is just zlib, but only turned on after a successful
     * authentication.  openssh servers may only offer this type because
     * they've had troubles with security holes in zlib in the past.
     */

    /* package */ int mWindowSize = DEFAULT_WINDOW_SIZE;
    /* package */ int mMaxPacketSize = DEFAULT_MAX_PACKET_SIZE;
    private int mInitialBannerTimeout = 15000;
    
    private Socket mSocket;
    private InputStream mInStream;
    private OutputStream mOutStream;
    /* package */ SecurityOptions mSecurityOptions;
    /* package */ Packetizer mPacketizer;
    private Kex mKexEngine;
    
    // negotiation:
    protected TransportDescription mDescription = null;
    
    // shared transport state:
    /* package */ String mLocalVersion;
    /* package */ String mRemoteVersion;
    /* package */ byte[] mLocalKexInit;
    /* package */ byte[] mRemoteKexInit;
    /* package */ byte mExpectedPacket;
    /* package */ boolean mInKex;
    /* package */ boolean mInitialKexDone;
    /* package */ byte[] mSessionID;
    /* package */ BigInteger mK;
    /* package */ byte[] mH;
    /* package */ Object mLock = new Object();
    
    // channels:
    /* package */ Channel[] mChannels;
    /* package */ Event[] mChannelEvents;
    
    /* package */ boolean mActive;
    /* package */ Event mCompletionEvent;
    private Event mClearToSend;
    /* package */ LogSink mLog;
    private IOException mSavedException;
    /* package */ AuthHandler mAuthHandler;
    private Message mGlobalResponse;
    private Map mMessageHandlers;       // Map<byte, MessageHandler>
    private Map mChannelFactoryMap;     // Map<String, Class> of registered channel types
}
