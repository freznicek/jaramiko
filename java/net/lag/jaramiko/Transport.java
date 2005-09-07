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
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.io.InterruptedIOException;
//import java.net.SocketTimeoutException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * An SSH Transport attaches to a socket, negotiates an encrypted session,
 * authenticates, and then creates stream tunnels, called {@link Channel}s, across
 * the session.  Multiple channels can be multiplexed across a single session
 * (and often are, in the case of port forwardings).  A Transport can operate
 * in either client or server mode.
 * 
 * @author robey
 */
public class Transport
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
    Transport (Socket socket)
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
        mSecurityOptions = new SecurityOptions(KNOWN_CIPHERS, KNOWN_MACS, KNOWN_KEYS, KNOWN_KEX);
        
        mChannels = new Channel[16];
        mChannelEvents = new Event[16];
        
        mSocket.setSoTimeout(100);
        mPacketizer = new Packetizer(mInStream, mOutStream, mRandom);
        mExpectedPacket = 0;
        mInitialKexDone = false;
        
        mLocalVersion = "SSH-" + PROTO_ID + "-" + CLIENT_ID;
        mRemoteVersion = null;
        
        mMessageHandlers = new HashMap();
        
        mServerAcceptLock = new Object();
        mServerAccepts = new ArrayList();
        mServerKeyMap = new HashMap();
    }
    
    /**
     * Set the logging mechanism for this Transport.  By default, log messages
     * are sent to a {@link NullLog} object.
     * 
     * @param logger the new logger to use
     */
    public void
    setLog (LogSink logger)
    {
        mLog = logger;
        mPacketizer.setLog(logger);
    }
    
    /**
     * Set whether packet contents should be logged as they arrive or depart.
     * Normally you only want this on for serious debugging; the log traffic
     * would otherwise be huge.
     * 
     * @param dump true if packet contents should be logged; false if not
     */
    public void
    setDumpPackets (boolean dump)
    {
        mPacketizer.setDumpPackets(dump);
    }
    
    /**
     * Return a {@link SecurityOptions} object which can be used to tweak the
     * encryption algorithms this transport will permit, and the order of
     * preference for them.  The preferred algorithms for encryption,
     * digest (hash), public key, and key exchange can be modified this way.
     * 
     * @return this Transport's SecurityOptions object
     */
    public SecurityOptions
    getSecurityOptions ()
    {
        return mSecurityOptions;
    }

    /**
     * Negotiate a new SSH2 session as a client.  This is the first step after
     * creating a new Transport.  A separate thread is created for protocol
     * negotiation, and this method blocks (up to a specified timeout) to find
     * out if it was successful.  If negotiation failed, an exception will be
     * thrown.
     *
     * <p>If a host key is passed in, host key checking will be done and an
     * exception will be thrown if the server's host key doesn't match.  If the
     * host key is <code>null</code>, no host key checking is done, and you
     * must do it yourself using {@link #getRemoteServerKey}.
     * 
     * <p>After a successful negotiation, you will usually want to
     * authenticate, calling {@link #authPassword} or {@link #authPrivateKey}.
     * Then you may call {@link #openSession} or {@link #openChannel} to get
     * a {@link Channel} for data transfer.
     * 
     * @param hostkey the host key expected from the server, or <code>null</code>
     *     to skip host key checking
     * @param timeout_ms maximum time (in milliseconds) to wait for negotiation
     *     to finish; <code>-1</code> to wait indefinitely
     * @throws SSHException if the SSH2 negotiation fails or the host key
     *     supplied by the server is incorrect
     * @throws IOException if there was an I/O exception on the socket
     */
    public void
    startClient (PKey hostkey, int timeout_ms)
        throws IOException
    {
        detectJavaSecurityBug();

        if (hostkey != null) {
            // we only want this particular key then
            mSecurityOptions.setKeys(Arrays.asList(new String[] { hostkey.getSSHName() }));
        }
        
        mCompletionEvent = new Event();
        mServerMode = false;
        mActive = true;
        new Thread(new Runnable() {
            public void run () {
                privateRun();
            }
        }, "paramikoj client feeder").start();

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
        
        // check the host key
        if (hostkey != null) {
            PKey skey = getRemoteServerKey();
            if (! skey.equals(hostkey)) {
                mLog.debug("Bad host key from server");
                mLog.debug("Expected: " + hostkey.getSSHName() + ": " + Util.encodeHex(hostkey.getFingerprint()));
                mLog.debug("Got     : " + skey.getSSHName() + ": " + Util.encodeHex(skey.getFingerprint()));
                throw new SSHException("Bad host key from server");
            }
            mLog.debug("Host key verified (" + skey.getSSHName() + ")");
        }
    }
    
    public void
    startServer (ServerInterface server, int timeout_ms)
        throws IOException
    {
        detectJavaSecurityBug();
        
        mServer = server;
        mCompletionEvent = new Event();
        mServerMode = true;
        mActive = true;
        new Thread(new Runnable() {
            public void run() {
                privateRun();
            }
        }, "paramikoj server feeder").start();
        
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
     * Return true if this session is active and has authenticated
     * successfully.
     * 
     * @return true if this session is active and authenticated
     */
    public boolean
    isAuthenticated ()
    {
        return mActive && (mAuthHandler != null) && mAuthHandler.isAuthenticated();
    }
    
    /**
     * Return the username this connection is authenticated for.  If the
     * session is not authenticated (or authentication failed), this method
     * returns null.
     * 
     * @return the username that was authenticated, or null
     */
    public String
    getUsername ()
    {
        if (! mActive || (mAuthHandler == null)) {
            return null;
        }
        return mAuthHandler.getUsername();
    }
    
    /**
     * Authenticate to the SSH2 server using a password.  The username and
     * password are sent over an encrypted link.
     * 
     * <p>This method blocks until authentication succeeds or fails.  On
     * failure, an exception is raised.  Otherwise, the method simply returns.
     * If the server requires multi-step authentication (which is very rare),
     * this method will return a list of auth types permissible for the next
     * step.  Otherwise, in the normal case, an empty list is returned.
     * 
     * @param username the username to authenticate as
     * @param password the password to authenticate with
     * @param timeout_ms how long to wait for a response (in milliseconds);
     *     <code>-1</code> to wait forever
     * @return a list of auth types permissible for the next step of
     *     authentication (normally empty, meaning authentication is complete)
     * @throws BadAuthenticationType if password authentication isn't allowed
     *     by the server for this user
     * @throws SSHException if the authentication failed
     * @throws IOException if an I/O exception occurred at the socket layer
     */
    public String[]
    authPassword (String username, String password, int timeout_ms)
        throws IOException
    {
        Event event = new Event();
        mAuthHandler = new AuthHandler(new MyTransportInterface(), mRandom, mLog);
        mAuthHandler.authPassword(username, password, event);
        return waitForAuthResponse(event, timeout_ms);
    }
    
    /**
     * Authenticate to the SSH2 server using a private key.  The key is used to
     * sign data from the server, so it must be a key capable of signing (not
     * just a public key).
     * 
     * <p>This method blocks until the authentication succeeds or fails.  On
     * failure, an exception is raised.  Otherwise, the method simply returns.
     * If the server requires multi-step authentication (which is very rare),
     * this method will return a list of auth types permissible for the next
     * step.  Otherwise, in the nromal case, an empty list is returned.
     * 
     * @param username the username to authenticate as
     * @param key the private key to authenticate with
     * @param timeout_ms how long to wait for a response (in milliseconds);
     *     <code>-1</code> to wait forever
     * @return a list of auth types permissible for the next step of
     *     authentication (normally empty, meaning authentication is complete)
     * @throws BadAuthenticationType if private key authentication isn't
     *     allowed by the server for this user
     * @throws SSHException if the authentication failed
     * @throws IOException if an I/O exception occurred at the socket layer
     */
    public String[]
    authPrivateKey (String username, PKey key, int timeout_ms)
        throws IOException
    {
        Event event = new Event();
        mAuthHandler = new AuthHandler(new MyTransportInterface(), mRandom, mLog);
        mAuthHandler.authPrivateKey(username, key, event);
        return waitForAuthResponse(event, timeout_ms);
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
    
    /**
     * Return the host key of the server (in client mode).
     * 
     * @return the public key of the remote server
     * @throws SSHException if no session is currently active
     */
    public PKey
    getRemoteServerKey ()
        throws SSHException
    {
        if (!mActive || !mInitialKexDone) {
            throw new SSHException("No existing session");
        }
        return mHostKey;
    }
    
    /**
     * Add a host key to the list of keys used for server mode.  When behaving
     * as a server, the host key is used to sign certain packets during the
     * SSH2 negotiation, so that the client can trust that we are who we say
     * we are.  Because this is used for signing, the key must contain private
     * key info, not just the public half.  Only one key of each type (RSA or
     * DSS) is kept.
     * 
     * @param key the host key to add
     */
    public void
    addServerKey (PKey key)
    {
        mServerKeyMap.put(key.getSSHName(), key);
    }
    
    /**
     * Return the active host key, in server mode.  After negotiating with the
     * client, this method will return the negotiated host key.  If only one
     * type of host key was set with {@link #addServerKey}, that's the only key
     * that will ever be returned.  But in cases where you have set more than
     * one type of host key (for example, an RSA key and a DSS key), the key
     * type will be negotiated by the client, and this method will return the
     * key of the type agreed on.  If the host key has not been negotiated
     * yet, null is returned.  In client mode, the behavior is undefined.
     * 
     * @return the host key being used for this session
     */
    public PKey
    getServerKey ()
    {
        return mServerKey;
    }
    
    /**
     * Turn on/off keepalive packets (default is off).  If this is set, after
     * <code>interval</code> milliseconds without sending any data over the
     * connection, a "keepalive" packet will be sent (and ignored by the
     * remote host).  This can be useful to keep connections alive over a
     * NAT, for example.
     * 
     * @param interval_ms milliseconds to wait before sending a keepalive
     *     packet (or 0 to disable keepalives)
     */
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
     * Force this session to switch to new keys.  Normally this is done
     * automatically after the session hits a certain number of packets or
     * bytes sent or received, but this method gives you the option of forcing
     * new keys whenever you want.  Negotiating new keys causes a pause in
     * traffic both ways as the two sides swap keys and do computations.  This
     * method returns when the session has switched to new keys, or the
     * session has died mid-negotiation.
     * 
     * @param timeout_ms time (in milliseconds) to wait for renegotiation
     * @return true on success, false if the timeout occurred first
     * @throws IOException if the renegotiation failed, or the connection was
     *     lost
     */
    public boolean
    renegotiateKeys (int timeout_ms)
        throws IOException
    {
        mCompletionEvent = new Event();
        sendKexInit();
        if (! waitForEvent(mCompletionEvent, timeout_ms)) {
            return false;
        }
        if (! mActive) {
            IOException x = getException();
            if (x != null) {
                throw x;
            } else {
                throw new SSHException("Negotiation failed.");
            }
        }
        return true;
    }
    
    /**
     * Send a junk packet across the encrypted link.  This is sometimes used
     * to add "noise" to a connection to confuse would-be attackers.  It can
     * also be used as a keep-alive for long lived connections traversing
     * firewalls.
     * 
     * <p>If <code>bytes</code> is 0, a random number of bytes from 10 to 41
     * will be attached.
     * 
     * @param bytes the number of random bytes to send in the payload of the
     *     ignored packet
     * @param timeout_ms time (in milliseconds) to wait for the request
     * @throws IOException if an exception occurs while sending the request
     */
    public void
    sendIgnore (int bytes, int timeout_ms)
        throws IOException
    {
        Message m = new Message();
        m.putByte(MessageType.IGNORE);
        if (bytes <= 0) {
            byte[] b = new byte[1];
            mRandom.nextBytes(b);
            bytes = (b[0] % 32) + 10;
        }
        byte[] data = new byte[bytes];
        mRandom.nextBytes(data);
        m.putBytes(data);
        sendUserMessage(m, timeout_ms);
    }
    
    /**
     * Make a global request to the remote host.  These are normally
     * extensions to the SSH2 protocol.
     * 
     * <p>If <code>timeout_ms</code> is greater than zero, a response is
     * requested from the server, and this method will wait up to the timeout
     * for a response.  The response will be returned as an SSH2
     * {@link Message}.
     * 
     * <p>If <code>timeout_ms</code> is zero (or -1), no response is
     * requested, and the method returns <code>null</code> immediately.
     * 
     * @param requestName name of the request to make
     * @param parameters an optional list of objects to attach to the request
     *     (see {@link Message#putAll} for a list of objects that can be
     *     attached); <code>null</code> to attach nothing
     * @param timeout_ms 0 to request no response; otherwise the maximum time
     *     to wait for a response from the server
     * @return the server's response, or <code>null</code> if the timeout was
     *     hit or no response was requested
     * @throws IOException if an I/O exception occurred on the socket
     */
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
    
    /**
     * Request a new channel to the server.  {@link Channel}s are socket-like
     * objects used for the actual transfer of data across an SSH session.
     * You may only request a channel after negotiating encryption (using
     * {@link #startClient}) and authenticating.
     * 
     * <p>For most cases, you should call {@link #openSession} instead.  This
     * is a more advanced interface.
     * 
     * @param kind the kind of channel requested (usually <code>"session"</code>,
     *     <code>"forwarded-tcpip"</code>, or <code>"direct-tcpip"</code>)
     * @param parameters any parameters required by the channel request type
     *     (may be null)
     * @param timeout_ms time (in milliseconds) to wait for the operation to
     *     complete
     * @return a new {@link Channel} on success
     * @throws IOException if there was an error making the request, or it was
     *     rejected by the server
     */
    public Channel
    openChannel (String kind, List parameters, int timeout_ms)
        throws IOException
    {
        if (! mActive) {
            throw new SSHException("No existing session.");
        }
        
        Event e = null;
        int chanid = 0;
        synchronized (mLock) {
            chanid = getNextChannel();
            
            Message m = new Message();
            m.putByte(MessageType.CHANNEL_OPEN);
            m.putString(kind);
            m.putInt(chanid);
            m.putInt(mWindowSize);
            m.putInt(mMaxPacketSize);
            if (parameters != null) {
                m.putAll(parameters);
            }
            
            Channel c = new Channel(chanid);
            mChannels[chanid] = c;
            e = new Event();
            mChannelEvents[chanid] = e;
            c.setTransport(new MyTransportInterface(), mLog);
            c.setWindow(mWindowSize, mMaxPacketSize);
            
            sendUserMessage(m, timeout_ms);
        }
        
        if (! waitForEvent(e, timeout_ms)) {
            IOException x = getException();
            if (x == null) {
                x = new SSHException("Unable to open channel.");
            }
            throw x;
        }
        
        synchronized (mLock) {
            Channel c = mChannels[chanid];
            if (c == null) {
                IOException x = getException();
                if (x == null) {
                    x = new SSHException("Unable to open channel.");
                }
                throw x;
            }
            return c;
        }
    }
    
    /**
     * Request a new channel to the server, of type <code>"session"</code>.
     * This is just an alias for <code>openChannel("session", null, timeout_ms)</code>.
     * 
     * @param timeout_ms time (in milliseconds) to wait for the request to
     *     compelte
     * @return a new {@link Channel} on success
     * @throws IOException if an exception occurs while sending the request,
     *     or the request is rejected
     */
    public Channel
    openSession (int timeout_ms)
        throws IOException
    {
        return openChannel("session", null, timeout_ms);
    }
    
    /**
     * Return the next channel opened by the client over this transport, in
     * server mode.  If no channel is opened before the given timeout, null
     * is returned.
     * 
     * @param timeout_ms time (in milliseconds) to wait for a channel, or 0
     *     to wait forever
     * @return a new Channel opened b the client
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
     * Close this session, and any open channels.
     */
    public void
    close ()
    {
        synchronized (mLock) {
            mActive = false;
            mPacketizer.close();
            for (int i = 0; i < mChannels.length; i++) {
                if (mChannels[i] != null) {
                    mChannels[i].unlink();
                }
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
    
    /* package */ final void
    verifyKey (byte[] hostKey, byte[] sig)
        throws SSHException
    {
        PKey key = PKey.createFromData(hostKey);
        mLog.debug("Server host key: " + Util.encodeHex(key.getFingerprint()));
        if (! key.verifySSHSignature(mH, new Message(sig))) {
            throw new SSHException("Signature verification (" + key.getSSHName() + ") failed.");
        }
        mHostKey = key;
    }
    
    /* Compute SSH2-style key bytes, using an "id" ('A' - 'F') and a pile of
     * state common to this session.
     */
    /* package */ final byte[]
    computeKey (byte id, int nbytes)
    {
        byte[] out = new byte[nbytes];
        int sofar = 0;
        MessageDigest sha = null;
        try {
            sha = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException x) {
            throw new RuntimeException("Unable to find SHA1: internal java error: " + x);
        }
        
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
            sha.update(m.toByteArray());
            byte[] digest = sha.digest();
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
    
    private final void
    activateInbound ()
        throws SSHException
    {
        try {
            // this method shouldn't be so long, but java makes this really difficult and bureaucratic
            CipherDescription desc = (CipherDescription) sCipherMap.get(mAgreedRemoteCipher);
            Cipher outCipher = Cipher.getInstance(desc.mJavaName);
            String algName = desc.mJavaName.split("/")[0];
            AlgorithmParameters param = AlgorithmParameters.getInstance(algName);
            byte[] key, iv;
            if (mServerMode) {
                key = computeKey((byte)'C', desc.mKeySize);
                iv = computeKey((byte)'A', desc.mBlockSize);
            } else {
                key = computeKey((byte)'D', desc.mKeySize);
                iv = computeKey((byte)'B', desc.mBlockSize);
            }
            param.init(new IvParameterSpec(iv));
            outCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algName), param);

            MacDescription mdesc = (MacDescription) sMacMap.get(mAgreedRemoteMac);
            Mac outMac = Mac.getInstance(mdesc.mJavaName);
            /* initial mac keys are done in the hash's natural size (not the
             * potentially truncated transmission size)
             */
            if (mServerMode) {
                key = computeKey((byte)'E', mdesc.mNaturalSize);
            } else {
                key = computeKey((byte)'F', mdesc.mNaturalSize);
            }
            outMac.init(new SecretKeySpec(key, mdesc.mJavaName));
            mPacketizer.setInboundCipher(outCipher, desc.mBlockSize, outMac, mdesc.mDigestSize);
        } catch (GeneralSecurityException x) {
            throw new SSHException("Internal java error: " + x);
        }
    }
    
    // switch on newly negotiated encryption parameters for outbound traffic
    /* package */ final void
    activateOutbound ()
        throws IOException
    {
        Message m = new Message();
        m.putByte(MessageType.NEW_KEYS);
        sendMessage(m);
        
        try {
            // this method shouldn't be so long, but java makes this really difficult and bureaucratic
            CipherDescription desc = (CipherDescription) sCipherMap.get(mAgreedLocalCipher);
            Cipher outCipher = Cipher.getInstance(desc.mJavaName);
            String algName = desc.mJavaName.split("/")[0];
            AlgorithmParameters param = AlgorithmParameters.getInstance(algName);
            byte[] key, iv;
            if (mServerMode) {
                key = computeKey((byte)'D', desc.mKeySize);
                iv = computeKey((byte)'B', desc.mBlockSize);
            } else {
                key = computeKey((byte)'C', desc.mKeySize);
                iv = computeKey((byte)'A', desc.mBlockSize);
            }
            param.init(new IvParameterSpec(iv));
            outCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algName), param);
            
            MacDescription mdesc = (MacDescription) sMacMap.get(mAgreedLocalMac);
            Mac outMac = Mac.getInstance(mdesc.mJavaName);
            /* initial mac keys are done in the hash's natural size (not the
             * potentially truncated transmission size)
             */
            if (mServerMode) {
                key = computeKey((byte)'F', mdesc.mNaturalSize);
            } else {
                key = computeKey((byte)'E', mdesc.mNaturalSize);
            }
            outMac.init(new SecretKeySpec(key, mdesc.mJavaName));
            mPacketizer.setOutboundCipher(outCipher, desc.mBlockSize, outMac, mdesc.mDigestSize);
            
            if (! mPacketizer.needRekey()) {
                mInKex = false;
            }
            // we always expect to receive NEW_KEYS now
            mExpectedPacket = MessageType.NEW_KEYS;
        } catch (GeneralSecurityException x) {
            throw new SSHException("Internal java error: " + x);
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
        if (! waitForEvent(mClearToSend, timeout_ms)) {
            return;
        }
        sendMessage(m);
    }
    
    /* package */ boolean
    isActive ()
    {
        return mActive;
    }

    
    // -----  private
    
    
    private void
    checkBanner ()
        throws IOException
    {
        String line = null;
        
        for (int i = 0; i < 5; i++) {
            // give them 5 seconds for the first line, then just 2 seconds each additional line
            int timeout = 2000;
            if (i == 0) {
                timeout = 5000;
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
    }
    
    private void
    sendKexInit ()
        throws IOException
    {
        mClearToSend.clear();
        
        byte[] rand = new byte[16];
        mRandom.nextBytes(rand);

        Message m = new Message();
        m.putByte(MessageType.KEX_INIT);
        m.putBytes(rand);
        m.putList(mSecurityOptions.getKex());
        m.putList(mSecurityOptions.getKeys());
        m.putList(mSecurityOptions.getCiphers());
        m.putList(mSecurityOptions.getCiphers());
        m.putList(mSecurityOptions.getDigests());
        m.putList(mSecurityOptions.getDigests());
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
    
    /**
     * Wait for an event to trigger, up to an optional timeout.  If the
     * transport goes inactive (dead), it will return prematurely within the
     * next tenth of a second.
     * It will also return prematurely if the thread is interrupted.
     *  
     * @param e the event to wait on
     * @param timeout_ms maximum time to wait (in milliseconds); -1 to wait
     *     forever
     * @return true if the event was triggered or the transport died; false if
     *     the timeout occurred or the thread was interrupted
     */
    private boolean
    waitForEvent (Event e, int timeout_ms)
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
                return true;
            }
        }
        return true;
    }
    
    private String[]
    waitForAuthResponse (Event e, int timeout_ms)
        throws IOException
    {
        if (! waitForEvent(e, timeout_ms)) {
            throw new SSHException("Timeout.");
        }
        if (! mActive) {
            IOException x = getException();
            if (x == null) {
                x = new SSHException("Authentication failed.");
            }
            throw x;
        }
        
        if (! mAuthHandler.isAuthenticated()) {
            IOException x = getException();
            if (x == null) {
                x = new SSHException("Authentication failed.");
            } else if (x instanceof PartialAuthentication) {
                return ((PartialAuthentication) x).getAllowedTypes();
            }
            throw x;
        }
        return new String[0];
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
        mLog.debug("Feeder thread terminating.");
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
        
        if (mServerMode && (mAuthHandler == null)) {
            // create auth handler for server mode
            mAuthHandler = new AuthHandler(new MyTransportInterface(), mRandom, mLog);
            mAuthHandler.useServerMode(mServer);
        }
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
        mClearToSend.set();
    }
    
    private void
    parseGlobalRequest (Message m)
        throws IOException
    {
        String kind = m.getString();
        boolean wantReply = m.getBoolean();
        mLog.debug("Received global request '" + kind + "'");
        List response = null;
        if (mServer != null) {
            response = mServer.checkGlobalRequest(kind, m);
        }
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
        
        // no compression support (yet?)
        List supportedCompressions = Arrays.asList(new String[] { "none" });
        if ((filter(supportedCompressions, clientCompressAlgorithmList) == null) ||
            (filter(supportedCompressions, serverCompressAlgorithmList) == null)) {
            throw new SSHException("Incompatible SSH peer");
        }
        mAgreedKex = mServerMode ? filter(kexAlgorithmList, mSecurityOptions.getKex()) :
            filter(mSecurityOptions.getKex(), kexAlgorithmList);
        if (mAgreedKex == null) {
            throw new SSHException("Incompatible SSH peer (no acceptable kex algorithm)");
        }
        mAgreedServerKey = mServerMode ? filter(serverKeyAlgorithmList, mSecurityOptions.getKeys()) :
            filter(mSecurityOptions.getKeys(), serverKeyAlgorithmList);
        if (mAgreedServerKey == null) {
            throw new SSHException("Incompatible SSH peer (no acceptable host key)");
        }
        if (mServerMode) {
            mServerKey = (PKey) mServerKeyMap.get(mAgreedServerKey);
            if (mServerKey == null) {
                throw new SSHException("Incompatible SSH peer (can't match requested host key type");
            }
        }

        if (mServerMode) {
            mAgreedLocalCipher = filter(serverEncryptAlgorithmList, mSecurityOptions.getCiphers());
            mAgreedRemoteCipher = filter(clientEncryptAlgorithmList, mSecurityOptions.getCiphers());
        } else {
            mAgreedLocalCipher = filter(mSecurityOptions.getCiphers(), clientEncryptAlgorithmList);
            mAgreedRemoteCipher = filter(mSecurityOptions.getCiphers(), serverEncryptAlgorithmList);
        }
        if ((mAgreedLocalCipher == null) || (mAgreedRemoteCipher == null)) {
            throw new SSHException("Incompatible SSH peer (no acceptable ciphers)");
        }
        
        if (mServerMode) {
            mAgreedLocalMac = filter(serverMacAlgorithmList, mSecurityOptions.getDigests());
            mAgreedRemoteMac = filter(clientMacAlgorithmList, mSecurityOptions.getDigests());
        } else {
            mAgreedLocalMac = filter(mSecurityOptions.getDigests(), clientMacAlgorithmList);
            mAgreedRemoteMac = filter(mSecurityOptions.getDigests(), serverMacAlgorithmList);
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
        mRemoteKexInit = new byte[m.getPosition()];
        System.arraycopy(data, 0, mRemoteKexInit, 0, m.getPosition());
        
        Class kexClass = (Class) sKexMap.get(mAgreedKex);
        if (kexClass == null) {
            throw new SSHException("Oops!  Negotiated kex " + mAgreedKex + " which I don't implement");
        }
        try {
            mKexEngine = (Kex) kexClass.newInstance();
        } catch (Exception x) {
            throw new SSHException("Internal java error: " + x);
        }
        mKexEngine.startKex(new MyTransportInterface(), mRandom);
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
        String reasonText = "(unknown code)";
        if ((reason > 0) && (reason < CONNECTION_FAILED_CODE.length)) {
            reasonText = CONNECTION_FAILED_CODE[reason];
        }
        mLog.notice("Secsh channel " + chanID + " open FAILED: " + reasonStr + ": " + reasonText);
        
        synchronized (mLock) {
            mChannels[chanID] = null;
            if (mChannelEvents[chanID] != null) {
                mChannelEvents[chanID].set();
                mChannelEvents[chanID] = null;
            }
        }
    }
    
    private void
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
        
        if (! mServerMode) {
            mLog.debug("Rejecting '" + kind + "' channel request from server.");
            reject = true;
            reason = ChannelError.ADMINISTRATIVELY_PROHIBITED;
        } else {
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
            c.setTransport(new MyTransportInterface(), mLog);
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
    
    // you are already holding mLock
    private int
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
     * many versions of java are crippled for no sane reason, and can't use
     * 256 bit ciphers.  detect that so we can warn the user and explain how
     * to fix it.
     */
    private void
    detectJavaSecurityBug ()
    {
        if (sCheckedBug) { 
            return;
        }
        
        boolean bug = false;
        
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            AlgorithmParameters param = AlgorithmParameters.getInstance("AES");
            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            param.init(new IvParameterSpec(iv));
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), param);
        } catch (GeneralSecurityException x) {
            bug = true;
        } catch (SecurityException x) {
            bug = true;
        }
        
        sCheckedBug = true;
        if (! bug) {
            return;
        }
        
        mLog.notice("Your java installation lacks support for 256-bit encryption.  " +
                    "This is due to a poor choice of defaults in Sun's java.  To fix it, " +
                    "visit: <http://java.sun.com/j2se/1.4.2/download.html> and download " +
                    "the \"unlimited strength\" files at the bottom of the page, under " +
                    "\"other downloads\".");
        
        for (Iterator i = sCipherMap.values().iterator(); i.hasNext(); ) {
            CipherDescription desc = (CipherDescription) i.next();
            if (desc.mKeySize > 16) {
                i.remove();
            }
        }
        mLog.notice("256-bit ciphers turned off.");
    }
    
    
    // ahhh java...  weird hoops to implement an interface only within this package
    private class MyTransportInterface
        implements TransportInterface
    {
        public byte[] getSessionID () { return Transport.this.mSessionID; }
        public boolean inServerMode () { return Transport.this.inServerMode(); }  
        public void expectPacket (byte ptype) { Transport.this.expectPacket(ptype); }
        public void saveException (IOException x) { Transport.this.saveException(x); }
        public void sendMessage (Message m) throws IOException { Transport.this.sendMessage(m); }
        public void sendUserMessage (Message m, int timeout_ms) throws IOException { Transport.this.sendUserMessage(m, timeout_ms); }
        public String getLocalVersion () { return mLocalVersion; }
        public String getRemoteVersion () { return mRemoteVersion; }
        public byte[] getLocalKexInit () { return mLocalKexInit; }
        public byte[] getRemoteKexInit () { return mRemoteKexInit; }
        public PKey getServerKey () { return mServerKey; }
        public void setKH (BigInteger k, byte[] h) { Transport.this.setKH(k, h); }
        public void verifyKey (byte[] hostKey, byte[] sig) throws SSHException { Transport.this.verifyKey(hostKey, sig); }
        public void registerMessageHandler (byte ptype, MessageHandler handler) { Transport.this.registerMessageHandler(ptype, handler); }
        public void activateOutbound () throws IOException { Transport.this.activateOutbound(); }
        public void unlinkChannel (int chanID) { synchronized (mLock) { mChannels[chanID] = null; } }
        public void close () { Transport.this.close(); }
    }
    
        
    private static final String PROTO_ID = "2.0";
    private static final String CLIENT_ID = "jaramiko_0.1";
    
    private static final String[] CONNECTION_FAILED_CODE = {
        "",
        "Administratively prohibited",
        "Connect failed",
        "Unknown channel type",
        "Resource shortage",
    };
    
    private static Map sCipherMap = new HashMap();
    private static Map sMacMap = new HashMap();
    private static Map sKeyMap = new HashMap();
    private static Map sKexMap = new HashMap();
    private static boolean sCheckedBug = false;
    
    static {
        // mappings from SSH protocol names to java implementation details
        sCipherMap.put("aes128-cbc", new CipherDescription("AES/CBC/NoPadding", 16, 16));
        sCipherMap.put("blowfish-cbc", new CipherDescription("Blowfish/CBC/NoPadding", 16, 8));
        sCipherMap.put("aes256-cbc", new CipherDescription("AES/CBC/NoPadding", 32, 16));
        sCipherMap.put("3des-cbc", new CipherDescription("DESede/CBC/NoPadding", 24, 8));

        sMacMap.put("hmac-sha1", new MacDescription("HmacSHA1", 20, 20));
        sMacMap.put("hmac-sha1-96", new MacDescription("HmacSHA1", 12, 20));
        sMacMap.put("hmac-md5", new MacDescription("HmacMD5", 16, 16));
        sMacMap.put("hmac-md5-96", new MacDescription("HmacMD5", 12, 16));
        
        sKeyMap.put("ssh-rsa", RSAKey.class);
        sKeyMap.put("ssh-dss", DSSKey.class);
        
        sKexMap.put("diffie-hellman-group1-sha1", KexGroup1.class);
    }
    
    private final String[] KNOWN_CIPHERS = { "aes128-cbc", "blowfish-cbc", "aes256-cbc", "3des-cbc" };
    private final String[] KNOWN_MACS = { "hmac-sha1", "hmac-md5", "hmac-sha1-96", "hmac-md5-96" };
    private final String[] KNOWN_KEYS = { "ssh-rsa", "ssh-dss" };
    private final String[] KNOWN_KEX = { "diffie-hellman-group1-sha1" };
    

    private int mWindowSize = 65536; 
    private int mMaxPacketSize = 32768;
    
    private Socket mSocket;
    private InputStream mInStream;
    private OutputStream mOutStream;
    private SecureRandom mRandom;
    private SecurityOptions mSecurityOptions;
    /* package */ Packetizer mPacketizer;
    private Kex mKexEngine;
    private Map mServerKeyMap;    // Map<String, PKey> of available keys
    private PKey mServerKey;      // server key (in server mode)
    private PKey mHostKey;        // server key (in client mode)
    private ServerInterface mServer;
    private Object mServerAcceptLock;
    private List mServerAccepts;
    
    // negotiation:
    private String mAgreedKex;
    private String mAgreedServerKey;
    /* package */ String mAgreedLocalCipher;
    /* package */ String mAgreedRemoteCipher;
    /* package */ String mAgreedLocalMac;
    /* package */ String mAgreedRemoteMac;
    
    // transport state:
    private String mLocalVersion;
    private String mRemoteVersion;
    private byte[] mLocalKexInit;
    private byte[] mRemoteKexInit;
    private byte mExpectedPacket;
    private boolean mInKex;
    private boolean mInitialKexDone;
    private byte[] mSessionID;
    private BigInteger mK;
    private byte[] mH;
    private Object mLock = new Object();
    
    // channels:
    private Channel[] mChannels;
    private Event[] mChannelEvents;
    
    private boolean mActive;
    private boolean mServerMode;
    private Event mCompletionEvent;
    private Event mClearToSend;
    private LogSink mLog;
    private IOException mSavedException;
    private AuthHandler mAuthHandler;
    private Message mGlobalResponse;
    private Map mMessageHandlers;       // Map<byte, MessageHandler>
}
