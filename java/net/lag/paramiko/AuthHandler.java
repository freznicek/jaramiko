/*
 * Created on May 30, 2005
 */

package net.lag.paramiko;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.List;

/**
 * @author robey
 */
/* package */ class AuthHandler
    implements MessageHandler
{
    public
    AuthHandler (TransportInterface t, SecureRandom random, LogSink log)
    {
        mTransport = t;
        mRandom = random;
        mLog = log;
        mAuthenticated = false;
    }
    
    public boolean
    isAuthenticated ()
    {
        return mAuthenticated;
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
    
    public boolean
    handleMessage (byte ptype, Message m)
        throws IOException
    {
        switch (ptype) {
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
        String lang = m.getString();
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
    
    
    private TransportInterface mTransport;
    private SecureRandom mRandom;
    private LogSink mLog;
    private Event mAuthEvent;
    private boolean mAuthenticated;
    
    // auth info
    private String mAuthMethod;
    private String mUsername;
    private String mPassword;
    private PKey mPrivateKey;
}
