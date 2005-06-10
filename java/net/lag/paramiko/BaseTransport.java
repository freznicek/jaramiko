/*
 * Copyright (C) 2005 Robey Pointer <robey@lag.net>
 *
 * This file is part of paramiko.
 *
 * Paramiko is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * Paramiko is distrubuted in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Paramiko; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 * 
 * 
 * Created on May 11, 2005
 */

package net.lag.paramiko;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
        mInitialKexDone = false;
        
        mLocalVersion = "SSH-" + PROTO_ID + "-" + CLIENT_ID;
        mRemoteVersion = null;
        
        mMessageHandlers = new HashMap();
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
        if (hostkey != null) {
            // we only want this particular key then
            mPreferredKeys = new String[] { hostkey.getSSHName() };
        }
        
        mCompletionEvent = new Event();
        mServerMode = false;
        mActive = true;
        new Thread(new Runnable() {
            public void run () {
                privateRun();
            }
        }).start();

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
        mAuthHandler = new AuthHandler(new BaseTransportInterface(), mRandom, mLog);
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
        mAuthHandler = new AuthHandler(new BaseTransportInterface(), mRandom, mLog);
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
        synchronized (this) {
            mSavedException = x;
        }
    }
    
    /* package */ IOException
    getException ()
    {
        synchronized (this) {
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
            mLog.error("I/O exception in transport thread: " + x);
            saveException(x);
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
        
        switch (ptype) {
        case MessageType.NEW_KEYS:
            parseNewKeys();
            return true;
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
        boolean alwaysDisplay = m.getBoolean();
        String text = m.getString();
        String lang = m.getString();
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
        mKexEngine.startKex(new BaseTransportInterface(), mRandom);
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
        public byte[] getSessionID () { return BaseTransport.this.mSessionID; }
        public boolean inServerMode () { return BaseTransport.this.inServerMode(); }  
        public void expectPacket (byte ptype) { BaseTransport.this.expectPacket(ptype); }
        public void saveException (IOException x) { BaseTransport.this.saveException(x); }
        public void sendMessage (Message m) throws IOException { BaseTransport.this.sendMessage(m); }
        public String getLocalVersion () { return mLocalVersion; }
        public String getRemoteVersion () { return mRemoteVersion; }
        public byte[] getLocalKexInit () { return mLocalKexInit; }
        public byte[] getRemoteKexInit () { return mRemoteKexInit; }
        public PKey getServerKey () { return mServerKey; }
        public void setKH (BigInteger k, byte[] h) { BaseTransport.this.setKH(k, h); }
        public void verifyKey (byte[] hostKey, byte[] sig) throws SSHException { BaseTransport.this.verifyKey(hostKey, sig); }
        public void registerMessageHandler (byte ptype, MessageHandler handler) { BaseTransport.this.registerMessageHandler(ptype, handler); }
        public void activateOutbound () throws IOException { BaseTransport.this.activateOutbound(); }
    }
    
        
    private static final String PROTO_ID = "2.0";
    private static final String CLIENT_ID = "paramikoj_0.1";
    
    private static Map sCipherMap = new HashMap();
    private static Map sMacMap = new HashMap();
    private static Map sKeyMap = new HashMap();
    private static Map sKexMap = new HashMap();
    
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
        //sKexMap.put("diffie-hellman-group-exchange-sha1", KexGex.class);
    }
    
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
    protected PKey mServerKey;
    protected PKey mHostKey;        // server key (in client mode)
    
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
    private boolean mInitialKexDone;
    private byte[] mSessionID;
    private BigInteger mK;
    private byte[] mH;
    
    protected boolean mActive;
    protected boolean mServerMode;
    protected Event mCompletionEvent;
    protected Event mClearToSend;
    protected LogSink mLog;
    private IOException mSavedException;
    private AuthHandler mAuthHandler;
    private Map mMessageHandlers;       // Map<byte, MessageHandler>
}
