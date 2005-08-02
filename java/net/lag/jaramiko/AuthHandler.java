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
 * Created on May 30, 2005
 */

package net.lag.jaramiko;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.List;

/**
 * @author robey
 */
/* package */ class AuthHandler
    implements MessageHandler
{
    /* package */
    AuthHandler (TransportInterface t, SecureRandom random, LogSink log)
    {
        mTransport = t;
        mRandom = random;
        mLog = log;
        mAuthenticated = false;
        mFailCount = 0;
    }
    
    /* package */ void
    useServerMode (ServerInterface server)
    {
        mServer = server;
        mTransport.registerMessageHandler(MessageType.SERVICE_REQUEST, this);
        mTransport.registerMessageHandler(MessageType.USERAUTH_REQUEST, this);
    }
    
    public boolean
    isAuthenticated ()
    {
        return mAuthenticated;
    }
    
    public String
    getUsername ()
    {
        return mUsername;
    }
    
    public void
    authPassword (String username, String password, Event event)
        throws IOException
    {
        synchronized (this) {
            mAuthEvent = event;
            mAuthMethod = "password";
            mUsername = username;
            mPassword = password;
            requestAuth();
        }
    }
    
    public void
    authPrivateKey (String username, PKey key, Event event)
        throws IOException
    {
        synchronized (this) {
            mAuthEvent = event;
            mAuthMethod = "publickey";
            mUsername = username;
            mPrivateKey = key;
            requestAuth();
        }
    }
    
    // called if the transport dies prematurely
    public void
    abort ()
    {
        if (mAuthEvent != null) {
            mAuthEvent.set();
        }
    }
    
    public boolean
    handleMessage (byte ptype, Message m)
        throws IOException
    {
        switch (ptype) {
        case MessageType.SERVICE_REQUEST:
            parseServiceRequest(m);
            return true;
        case MessageType.SERVICE_ACCEPT:
            parseServiceAccept(m);
            return true;
        case MessageType.USERAUTH_BANNER:
            parseBanner(m);
            return true;
        case MessageType.USERAUTH_FAILURE:
            parseAuthFailure(m);
            return true;
        case MessageType.USERAUTH_SUCCESS:
            parseAuthSuccess(m);
            return true;
        case MessageType.USERAUTH_REQUEST:
            parseAuthRequest(m);
            return true;
        }
        return true;
    }
    
    
    private void
    requestAuth ()
        throws IOException
    {
        Message m = new Message();
        m.putByte(MessageType.SERVICE_REQUEST);
        m.putString("ssh-userauth");
        /* a weird quirk of the ssh2 protocol is that "ssh-userauth" is the
         * ONLY service request ever made.
         */
        mTransport.registerMessageHandler(MessageType.SERVICE_ACCEPT, this);
        mTransport.registerMessageHandler(MessageType.USERAUTH_BANNER, this);
        mTransport.sendMessage(m);
    }

    private byte[]
    getSessionBlob (PKey key, String service, String username)
    {
        Message m = new Message();
        m.putByteString(mTransport.getSessionID());
        m.putByte(MessageType.USERAUTH_REQUEST);
        m.putString(username);
        m.putString(service);
        m.putString("publickey");
        m.putBoolean(true);
        m.putString(key.getSSHName());
        m.putByteString(key.toByteArray());
        return m.toByteArray();
    }
    
    private void
    parseServiceAccept (Message m)
        throws IOException
    {
        String service = m.getString();
        if (! service.equals("ssh-userauth")) {
            mLog.debug("Service request '" + service + "' accepted (?)");
            return;
        }
        mLog.debug("Userauth is OK");
        
        m = new Message();
        m.putByte(MessageType.USERAUTH_REQUEST);
        m.putString(mUsername);
        m.putString("ssh-connection");
        m.putString(mAuthMethod);
        if (mAuthMethod.equals("password")) {
            m.putBoolean(false);
            m.putString(mPassword);
        } else if (mAuthMethod.equals("publickey")) {
            m.putBoolean(true);
            m.putString(mPrivateKey.getSSHName());
            m.putByteString(mPrivateKey.toByteArray());
            byte[] blob = getSessionBlob(mPrivateKey, "ssh-connection", mUsername);
            m.putByteString(mPrivateKey.signSSHData(mRandom, blob).toByteArray());
        } else {
            throw new SSHException("Unknown auth method '" + mAuthMethod + "'");
        }
        mTransport.registerMessageHandler(MessageType.USERAUTH_SUCCESS, this);
        mTransport.registerMessageHandler(MessageType.USERAUTH_FAILURE, this);
        mTransport.sendMessage(m);
    }
    
    private void
    parseBanner (Message m)
        throws IOException
    {
        String banner = m.getString();
        m.getString();      // lang
        mLog.notice("Auth banner: " + banner);
        // who cares.
    }
    
    private void
    parseAuthFailure (Message m)
    {
        List authList = m.getList();
        String[] auths = (String[]) authList.toArray(new String[0]);
        boolean partial = m.getBoolean();
        if (partial) {
            mLog.notice("Authentication continues...");
            mLog.debug("Methods: " + Util.join(auths, ", "));
            mTransport.saveException(new PartialAuthentication(auths));
        } else if (authList.contains(mAuthMethod)) {
            mLog.notice("Authentication failed.");
        } else {
            mLog.notice("Authentication type not permitted.");
            mLog.debug("Allowed methods: " + Util.join(auths, ", "));
            mTransport.saveException(new BadAuthenticationType(auths));
        }
        mAuthenticated = false;
        mUsername = null;
        mAuthEvent.set();
    }
    
    private void
    parseAuthSuccess (Message m)
    {
        mLog.notice("Authentication successful!");
        mAuthenticated = true;
        mAuthEvent.set();
    }
    
    
    //  server mode
    
    
    private void
    disconnectServiceNotAvailable ()
        throws IOException
    {
        Message m = new Message();
        m.putByte(MessageType.DISCONNECT);
        m.putInt(DISCONNECT_SERVICE_NOT_AVAILABLE);
        m.putString("Service not available");
        m.putString("en");
        mTransport.sendMessage(m);
        mTransport.close();
    }
    
    private void
    disconnectNoMoreAuth ()
        throws IOException
    {
        Message m = new Message();
        m.putByte(MessageType.DISCONNECT);
        m.putInt(DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE);
        m.putString("No more auth methods available");
        m.putString("en");
        mTransport.sendMessage(m);
        mTransport.close();
    }

    private void
    parseServiceRequest (Message m)
        throws IOException
    {
        String service = m.getString();
        if (service.equals("ssh-userauth")) {
            Message mx = new Message();
            mx.putByte(MessageType.SERVICE_ACCEPT);
            mx.putString(service);
            mTransport.sendMessage(mx);
            return;
        }
        // dunno this one
        disconnectServiceNotAvailable();
    }
    
    private void
    parseAuthRequest (Message m)
        throws IOException
    {
        if (mAuthenticated) {
            // ignore
            return;
        }
        
        String username = m.getString();
        String service = m.getString();
        String method = m.getString();
        mLog.debug("Auth request (type=" + method + ") service=" + service + ", username=" + username);
        
        if (! service.equals("ssh-connection")) {
            disconnectServiceNotAvailable();
            return;
        }
        if ((mUsername != null) && ! mUsername.equals(username)) {
            mLog.warning("Auth rejected because the client attempted to change username in mid-flight");
            disconnectNoMoreAuth();
            return;
        }
        mUsername = username;
        
        int result = AuthError.FAILED;
        if (method.equals("none")) {
            result = mServer.checkAuthNone(username);
        } else if (method.equals("password")) {
            boolean changeReq = m.getBoolean();
            String password = m.getString();
            if (changeReq) {
                /* always treated as a failure, since we don't support
                 * changing passwords, but collect the list of valid auth
                 * types from the callback anyway
                 */
                mLog.debug("Auth request to change passwords (rejected)");
                m.getString();      // new password
                result = AuthError.FAILED;
            } else {
                result = mServer.checkAuthPassword(username, password);
            }
        } else if (method.equals("publickey")) {
            boolean sigAttached = m.getBoolean();
            String keyType = m.getString();
            byte[] keyBlob = m.getByteString();
            PKey key = null;
            try {
                key = PKey.createFromMessage(new Message(keyBlob));
            } catch (SSHException x) {
                mLog.notice("Auth rejected: public key: " + x);
                disconnectNoMoreAuth();
                return;
            }
            
            // first check if this key is okay... if not, we can skip verifying it
            result = mServer.checkAuthPublicKey(username, key);
            if (result != AuthError.FAILED) {
                // okay, verify it
                if (! sigAttached) {
                    /* client was just asking if this key was acceptable,
                     * before bothering to sign anything.  say it's okay.
                     */
                    Message mx = new Message();
                    mx.putByte(MessageType.USERAUTH_PK_OK);
                    mx.putString(keyType);
                    mx.putByteString(keyBlob);
                    mTransport.sendMessage(mx);
                    return;
                }
                Message sig = new Message(m.getByteString());
                byte[] blob = getSessionBlob(key, service, username);
                if (! key.verifySSHSignature(blob, sig)) {
                    mLog.notice("Auth rejected: invalid signature");
                    result = AuthError.FAILED;
                }
            }
        } else {
            result = mServer.checkAuthNone(username);
        }
        
        // okay, send result
        Message mx = new Message();
        if (result == AuthError.SUCCESS) {
            mLog.notice("Auth granted (" + method + ")");
            mx.putByte(MessageType.USERAUTH_SUCCESS);
            mAuthenticated = true;
        } else {
            mLog.notice("Auth rejected (" + method + ")");
            mx.putByte(MessageType.USERAUTH_FAILURE);
            mx.putString(mServer.getAllowedAuths(username));
            if (result == AuthError.PARTIAL_SUCCESS) {
                mx.putBoolean(true);
            } else {
                mx.putBoolean(false);
                mFailCount++;
            }
        }
        mTransport.sendMessage(mx);
        if (mFailCount >= 10) {
            disconnectNoMoreAuth();
        }
    }
    
    
    private static final int DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
    //private static final int DISCONNECT_AUTH_CANCELLED_BY_USER = 13;
    private static final int DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
    
    private TransportInterface mTransport;
    private SecureRandom mRandom;
    private LogSink mLog;
    private ServerInterface mServer;
    private Event mAuthEvent;
    private boolean mAuthenticated;
    private int mFailCount;
    
    // auth info
    private String mAuthMethod;
    private String mUsername;
    private String mPassword;
    private PKey mPrivateKey;
}
