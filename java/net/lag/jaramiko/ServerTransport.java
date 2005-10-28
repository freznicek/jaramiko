/*
 * Copyright (C) 2005 Robey Pointer <robey@lag.net>
 *
 * This file is part of paramiko.
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
 * 
 * 
 * Created on May 11, 2005
 */

package net.lag.jaramiko;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.lag.crai.Crai;
import net.lag.crai.CraiCipher;
import net.lag.crai.CraiDigest;
import net.lag.crai.CraiException;


public class ServerTransport
    extends BaseTransport
{
    // clean interface between Kex and Transport for unit testing
    private class MyKexTransportInterface
        implements KexTransportInterface
    {
        public String
        getLocalVersion ()
        {
            return mLocalVersion;
        }
        
        public String
        getRemoteVersion ()
        {
            return mRemoteVersion;
        }
        
        public byte[]
        getLocalKexInit ()
        {
            return mLocalKexInit;
        }
        
        public byte[]
        getRemoteKexInit ()
        {
            return mRemoteKexInit;
        }

        public void
        registerMessageHandler (byte ptype, MessageHandler handler)
        {
            ServerTransport.this.registerMessageHandler(ptype, handler);
        }
        
        public void
        expectPacket (byte ptype)
        {
            ServerTransport.this.expectPacket(ptype);
        }
        
        public void
        sendMessage (Message m)
            throws IOException
        {
            ServerTransport.this.sendMessage(m);
        }
        
        public PKey
        getServerKey ()
        {
            return ServerTransport.this.getServerKey();
        }
        
        public void
        verifyKey (byte[] hostKey, byte[] sig)
            throws SSHException
        {
            // no remote server key in server mode
            throw new SSHException("internal paramiko error");
        }

        public void
        setKH (BigInteger k, byte[] h)
        {
            ServerTransport.this.setKH(k, h);
        }
        
        public void
        kexComplete ()
            throws IOException
        {
            ServerTransport.this.activateOutbound();
        }
    }

    
    // FIXME: this isn't actually different from client to server
    private class MyChannelTransportInterface
        implements ChannelTransportInterface
    {
        public void
        sendUserMessage (Message m, int timeout_ms)
            throws IOException
        {
            ServerTransport.this.sendUserMessage(m, timeout_ms);
        }
        
        public void
        unlinkChannel (int chanID)
        {
            synchronized (mLock) {
                mChannels[chanID] = null;
            }
        }
    }

    
    public
    ServerTransport (Socket socket)
        throws IOException
    {
        super(socket);
        
        mServerAcceptLock = new Object();
        mServerAccepts = new ArrayList();
        mServerKeyMap = new HashMap();
    }

    /**
     * Negotiate a new SSH2 session as a server.  This is the first step after
     * creating a new Transport.  A separate thread is created for protocol
     * negotiation, and this method blocks (up to a specified timeout) to find
     * out if it was successful.  If negotiation failed, an exception will be
     * thrown.
     *
     * <p>After a successful negotiation, the client will usually try to
     * authenticate and open one or more {@link Channel}s.  Methods in
     * {@link ServerInterface} will be called to handle the authentication and
     * check permissions.  If everything succeeds, newly-opened channels will
     * appear via the {@link #accept} method.
     * 
     * @param server a callback object used for authentication and permission
     *     checking
     * @param timeout_ms maximum time (in milliseconds) to wait for negotiation
     *     to finish; <code>-1</code> to wait indefinitely
     * @throws SSHException if the SSH2 negotiation fails
     * @throws IOException if there was an I/O exception on the socket
     */
    public void
    start (ServerInterface server, int timeout_ms)
        throws IOException
    {
        detectUnsupportedCiphers();
        
        mServer = server;
        mCompletionEvent = new Event();
        mActive = true;
        new Thread(new Runnable() {
            public void run() {
                mLog.debug("starting thread (server mode): " + Integer.toHexString(this.hashCode()));
                transportRun();
            }
        }, "jaramiko server feeder").start();
        
        if (! waitForEvent(mCompletionEvent, timeout_ms)) {
            throw new SSHException("Timeout.");
        }
        if (! mActive) {
            IOException x = getException();
            if (x != null) {
                throw x;
            } else {
                throw new SSHException("Negotiation failed.");
            }
        }
    }
    
    /**
     * Set a banner to be sent during authentication in server mode.  This
     * method should be called before {@link #start} in order to
     * guarantee that it gets sent.
     *  
     * @param banner the authentication banner to advertise
     */
    public void
    setServerBanner (String banner)
    {
        mBanner = banner;
    }
    
    /**
     * Add a host key to the list of keys used for server mode.  The host key
     * is used to sign certain packets during the SSH2 negotiation, so that
     * the client can trust that we are who we say we are.  Because this is
     * used for signing, the key must contain private key info, not just the
     * public half.
     * 
     * <p>Only one key of each type (RSA or DSS) is kept.  If more than one
     * key type is set, the client gets to choose which type it prefers.
     * 
     * @param key the host key to add
     */
    public void
    addServerKey (PKey key)
    {
        mServerKeyMap.put(key.getSSHName(), key);
    }
    
    /**
     * Return the active host key.  After negotiating with the
     * client, this method will return the negotiated host key.  If only one
     * type of host key was set with {@link #addServerKey}, that's the only key
     * that will ever be returned.  But in cases where you have set more than
     * one type of host key (for example, an RSA key and a DSS key), the key
     * type will be negotiated by the client, and this method will return the
     * key of the type agreed on.  If the host key has not been negotiated
     * yet, null is returned.
     * 
     * @return the host key being used for this session
     */
    public PKey
    getServerKey ()
    {
        return mServerKey;
    }

    /**
     * Return the next channel opened by the client over this transport.  If
     * no channel is opened before the given timeout, null is returned.
     * 
     * @param timeout_ms time (in milliseconds) to wait for a channel, or 0
     *     to wait forever
     * @return a new Channel opened by the client
     */
    public Channel
    accept (int timeout_ms)
    {
        synchronized (mServerAcceptLock) {
            if (mServerAccepts.size() > 0) {
                return (Channel) mServerAccepts.remove(0);
            }
            
            try {
                mServerAcceptLock.wait(timeout_ms);
            } catch (InterruptedException x) {
                Thread.currentThread().interrupt();
            }
            
            if (mServerAccepts.size() > 0) {
                return (Channel) mServerAccepts.remove(0);
            }
            return null;
        }
    }
    
    /**
     * Set a crypto library provider for paramiko.  This setting affects all
     * Transport objects (both ClientTransport and ServerTransport), present
     * and future, and usually will only need to be set once (or never).
     * The only time you really need to set this is if you're using a
     * non-standard crypto provider (like on an embedded platform).
     * 
     * <p>If no crypto provider is set, paramiko will attempt to use JCE,
     * which comes standard with java 1.4 and up.
     * 
     * @param crai the crypto provider to use
     */
    public static void
    setCrai (Crai crai)
    {
        sCrai = crai;
    }
    
    
    // ------  package
    
    
    /* package */ KexTransportInterface
    createKexTransportInterface ()
    {
        return new MyKexTransportInterface();
    }

    // in server mode, flip the args around so the client's prefs take precedence
    /* package */ String
    filter (List clientPrefs, List serverPrefs)
    {
        return super.filter(serverPrefs, clientPrefs);
    }

    /* package */ final void
    activateInbound (CipherDescription desc, MacDescription mdesc)
        throws SSHException
    {
        try {
            // this method shouldn't be so long, but java makes this really difficult and bureaucratic
            CraiCipher inCipher = sCrai.getCipher(desc.mAlgorithm);
            byte[] key = computeKey((byte)'C', desc.mKeySize);
            byte[] iv = computeKey((byte)'A', desc.mBlockSize);
            inCipher.initDecrypt(key, iv);

            /* initial mac keys are done in the hash's natural size (not the
             * potentially truncated transmission size)
             */
            key = computeKey((byte)'E', mdesc.mNaturalSize);
            CraiDigest inMac = null;
            if (mdesc.mName == "MD5") {
                inMac = sCrai.makeMD5HMAC(key);
            } else {
                inMac = sCrai.makeSHA1HMAC(key);
            }
            mPacketizer.setInboundCipher(inCipher, desc.mBlockSize, inMac, mdesc.mDigestSize);
        } catch (CraiException x) {
            throw new SSHException("Internal java error: " + x);
        }
    }

    /* package */ final void
    activateOutbound (CipherDescription desc, MacDescription mdesc)
        throws SSHException
    {
        try {
            // this method shouldn't be so long, but java makes this really difficult and bureaucratic
            CraiCipher outCipher = sCrai.getCipher(desc.mAlgorithm);
            byte[] key = computeKey((byte)'D', desc.mKeySize);
            byte[] iv = computeKey((byte)'B', desc.mBlockSize);
            outCipher.initEncrypt(key, iv);
            
            /* initial mac keys are done in the hash's natural size (not the
             * potentially truncated transmission size)
             */
            key = computeKey((byte)'F', mdesc.mNaturalSize);
            CraiDigest outMac = null;
            if (mdesc.mName == "MD5") {
                outMac = sCrai.makeMD5HMAC(key);
            } else {
                outMac = sCrai.makeSHA1HMAC(key);
            }
    
            mPacketizer.setOutboundCipher(outCipher, desc.mBlockSize, outMac, mdesc.mDigestSize);
        } catch (CraiException x) {
            throw new SSHException("Internal java error: " + x);
        }
    }

    /* package */ void
    parseNewKeysHook ()
    {
        if (mAuthHandler == null) {
            mAuthHandler = new AuthHandler(this, sCrai, mLog);
            mAuthHandler.useServerMode(mServer, mBanner);
        }
    }
    
    /* package */ void
    kexInitHook ()
        throws SSHException
    {
        mServerKey = (PKey) mServerKeyMap.get(mAgreedServerKey);
        if (mServerKey == null) {
            throw new SSHException("Incompatible SSH peer (can't match requested host key type");
        }
        
        // swap sense of "local" and "remote"
        String temp = mAgreedLocalCipher;
        mAgreedLocalCipher = mAgreedRemoteCipher;
        mAgreedRemoteCipher = temp;
        
        temp = mAgreedLocalMac;
        mAgreedLocalMac = mAgreedRemoteMac;
        mAgreedRemoteMac = temp;
    }

    /* package */ List
    checkGlobalRequest (String kind, Message m)
    {
        return mServer.checkGlobalRequest(kind, m);
    }
    
    /* package */ void
    parseChannelOpen (Message m)
        throws IOException
    {
        String kind = m.getString();
        int reason = ChannelError.SUCCESS;
        int chanID = m.getInt();
        int initialWindowSize = m.getInt();
        int maxPacketSize = m.getInt();
        
        boolean reject = false;
        int myChanID = 0;
        Channel c = null;
        
        synchronized (mLock) {
            myChanID = getNextChannel();
            c = new Channel(myChanID);
            mChannels[myChanID] = c;
        }
        
        reason = mServer.checkChannelRequest(kind, myChanID);
        if (reason != ChannelError.SUCCESS) {
            mLog.debug("Rejecting '" + kind + "' channel request from client.");
            reject = true;
        }
        
        if (reject) {
            if (c != null) {
                synchronized (mLock) {
                    mChannels[myChanID] = null;
                }
            }
            
            Message mx = new Message();
            mx.putByte(MessageType.CHANNEL_OPEN_FAILURE);
            mx.putInt(chanID);
            mx.putInt(reason);
            mx.putString("");
            mx.putString("en");
            sendMessage(mx);
            return;
        }
        
        synchronized (mLock) {
            c.setTransport(new MyChannelTransportInterface(), mLog);
            c.setWindow(mWindowSize, mMaxPacketSize);
            c.setRemoteChannel(chanID, initialWindowSize, maxPacketSize);
            c.setServer(mServer);
        }
        
        Message mx = new Message();
        mx.putByte(MessageType.CHANNEL_OPEN_SUCCESS);
        mx.putInt(chanID);
        mx.putInt(myChanID);
        mx.putInt(mWindowSize);
        mx.putInt(mMaxPacketSize);
        sendMessage(mx);
        
        mLog.notice("Secsh channel " + myChanID + " opened.");

        synchronized (mServerAcceptLock) {
            mServerAccepts.add(c);
            mServerAcceptLock.notify();
        }
    }

    
    private ServerInterface mServer;
    private Map mServerKeyMap;    // Map<String, PKey> of available keys
    private PKey mServerKey;      // server key that was used for this session
    private String mBanner;

    private Object mServerAcceptLock;
    private List mServerAccepts;
}
