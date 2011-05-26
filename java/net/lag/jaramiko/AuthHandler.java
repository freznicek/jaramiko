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

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import net.lag.crai.Crai;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class AuthHandler implements MessageHandler {
    private static final Logger logger = LoggerFactory
            .getLogger(AuthHandler.class);

    @Deprecated
    AuthHandler(BaseTransport t, Crai crai, LogSink log) {
        this(t, crai);
    }

    AuthHandler(BaseTransport t, Crai crai) {
        mTransport = t;
        mCrai = crai;
        mAuthenticated = false;
        mFailCount = 0;
    }

    /* package */void useServerMode(ServerInterface server, String banner) {
        mServer = server;
        mBanner = banner;
        mTransport.registerMessageHandler(MessageType.SERVICE_REQUEST, this);
        mTransport.registerMessageHandler(MessageType.USERAUTH_REQUEST, this);
    }

    /* package */void setBannerListener(BannerListener listener) {
        mBannerListener = listener;
    }

    public boolean isAuthenticated() {
        return mAuthenticated;
    }

    public String getUsername() {
        return mUsername;
    }

    public void authNone(String username, Event event) throws IOException {
        synchronized (this) {
            mAuthEvent = event;
            mAuthMethod = "none";
            mUsername = username;
            requestAuth();
        }
    }

    public void authPassword(String username, String password, Event event)
            throws IOException {
        synchronized (this) {
            mAuthEvent = event;
            mAuthMethod = "password";
            mUsername = username;
            mPassword = password;
            requestAuth();
        }
    }

    public void authPrivateKey(String username, PKey key, Event event)
            throws IOException {
        synchronized (this) {
            mAuthEvent = event;
            mAuthMethod = "publickey";
            mUsername = username;
            mPrivateKey = key;
            requestAuth();
        }
    }

    public void authInteractive(String username, InteractiveHandler handler,
            Event event, String[] submethods) throws IOException {
        synchronized (this) {
            mAuthEvent = event;
            mAuthMethod = "keyboard-interactive";
            mUsername = username;
            mInteractiveHandler = handler;
            mSubmethods = submethods;
            requestAuth();
        }
    }

    // called if the transport dies prematurely
    public void abort() {
        if (mAuthEvent != null) {
            mAuthEvent.set();
        }
    }

    public boolean handleMessage(byte ptype, Message m) throws IOException {
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
        case MessageType.USERAUTH_INFO_REQUEST:
            parseInfoRequest(m);
            return true;
        case MessageType.USERAUTH_INFO_RESPONSE:
            parseInfoResponse(m);
            return true;
        }
        return true;
    }

    private void requestAuth() throws IOException {
        Message m = new Message();
        m.putByte(MessageType.SERVICE_REQUEST);
        m.putString("ssh-userauth");
        /*
         * a weird quirk of the ssh2 protocol is that "ssh-userauth" is the ONLY
         * service request ever made.
         */
        mTransport.registerMessageHandler(MessageType.SERVICE_ACCEPT, this);
        mTransport.registerMessageHandler(MessageType.USERAUTH_BANNER, this);
        mTransport.sendMessage(m);
    }

    private byte[] getSessionBlob(PKey key, String service, String username) {
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

    private void parseServiceAccept(Message m) throws IOException {
        String service = m.getString();
        if (!service.equals("ssh-userauth")) {
            logger.debug("Service request '{}' accepted (?)", service);
            return;
        }
        logger.debug("Userauth is OK");

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
            byte[] blob = getSessionBlob(mPrivateKey, "ssh-connection",
                    mUsername);
            m.putByteString(mPrivateKey.signSSHData(mCrai, blob).toByteArray());
        } else if (mAuthMethod.equals("keyboard-interactive")) {
            m.putString("");
            if (mSubmethods == null) {
                m.putString("");
            } else {
                m.putList(Arrays.asList(mSubmethods));
            }
            mTransport.registerMessageHandler(
                    MessageType.USERAUTH_INFO_REQUEST, this);
        } else if (mAuthMethod.equals("none")) {
            // nothing
        } else {
            throw new SSHException("Unknown auth method '" + mAuthMethod + "'");
        }
        mTransport.registerMessageHandler(MessageType.USERAUTH_SUCCESS, this);
        mTransport.registerMessageHandler(MessageType.USERAUTH_FAILURE, this);
        mTransport.sendMessage(m);
    }

    private void parseBanner(Message m) throws IOException {
        String banner = m.getString();
        m.getString(); // lang
        logger.info("Auth banner: {}", banner);
        if (mBannerListener != null) {
            mBannerListener.authenticationBannerEvent(banner);
        }
    }

    private void parseAuthFailure(Message m) {
        List<String> authList = m.getList();
        String[] auths = authList.toArray(new String[authList.size()]);
        boolean partial = m.getBoolean();
        if (partial) {
            logger.info("Authentication continues...");
            logger.debug("Methods: {}", Util.join(auths, ", "));
            mTransport.saveException(new PartialAuthentication(auths));
        } else if (authList.contains(mAuthMethod)) {
            logger.info("Authentication failed.");
        } else {
            logger.info("Authentication type not permitted.");
            logger.debug("Allowed methods: {}", Util.join(auths, ", "));
            mTransport.saveException(new BadAuthenticationType(auths));
        }
        mAuthenticated = false;
        mUsername = null;
        mAuthEvent.set();
    }

    private void parseAuthSuccess(Message m) {
        logger.info("Authentication successful!");
        mAuthenticated = true;
        mTransport.authTrigger();
        mAuthEvent.set();
    }

    private void parseInfoRequest(Message m) throws IOException {
        if (!mAuthMethod.equals("keyboard-interactive")) {
            throw new SSHException("Illegal info request from the server");
        }

        InteractiveQuery query = new InteractiveQuery();
        query.title = m.getString();
        query.instructions = m.getString();
        m.getString(); // lang
        int n = m.getInt();
        query.prompts = new InteractiveQuery.Prompt[n];
        for (int i = 0; i < n; i++) {
            query.prompts[i] = new InteractiveQuery.Prompt();
            query.prompts[i].text = m.getString();
            query.prompts[i].echoResponse = m.getBoolean();
        }
        String[] responses = mInteractiveHandler
                .handleInteractiveRequest(query);

        Message mx = new Message();
        mx.putByte(MessageType.USERAUTH_INFO_RESPONSE);
        mx.putInt(responses.length);
        for (int i = 0; i < responses.length; i++) {
            mx.putString(responses[i]);
        }
        mTransport.sendMessage(mx);
    }

    // server mode

    private void disconnectServiceNotAvailable() throws IOException {
        Message m = new Message();
        m.putByte(MessageType.DISCONNECT);
        m.putInt(DISCONNECT_SERVICE_NOT_AVAILABLE);
        m.putString("Service not available");
        m.putString("en");
        mTransport.sendMessage(m);
        mTransport.close();
    }

    private void disconnectNoMoreAuth() throws IOException {
        Message m = new Message();
        m.putByte(MessageType.DISCONNECT);
        m.putInt(DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE);
        m.putString("No more auth methods available");
        m.putString("en");
        mTransport.sendMessage(m);
        mTransport.close();
    }

    private void sendAuthResult(String username, String method, int result)
            throws IOException {
        Message m = new Message();
        if (result == AuthError.SUCCESS) {
            logger.info("Auth granted ({})", method);
            m.putByte(MessageType.USERAUTH_SUCCESS);
            mAuthenticated = true;
        } else {
            logger.info("Auth rejected ({})", method);
            m.putByte(MessageType.USERAUTH_FAILURE);
            m.putString(mServer.getAllowedAuths(username));
            if (result == AuthError.PARTIAL_SUCCESS) {
                m.putBoolean(true);
            } else {
                m.putBoolean(false);
                mFailCount++;
            }
        }
        mTransport.sendMessage(m);
        if (mFailCount >= 10) {
            disconnectNoMoreAuth();
        }
        if (result == AuthError.SUCCESS) {
            mTransport.authTrigger();
        }
    }

    private void parseServiceRequest(Message m) throws IOException {
        String service = m.getString();
        if (!service.equals("ssh-userauth")) {
            // dunno this one
            disconnectServiceNotAvailable();
            return;
        }

        Message mx = new Message();
        mx.putByte(MessageType.SERVICE_ACCEPT);
        mx.putString(service);
        mTransport.sendMessage(mx);

        if (mBanner != null) {
            // send auth banner
            mx = new Message();
            mx.putByte(MessageType.USERAUTH_BANNER);
            mx.putString(mBanner);
            mx.putString("");
            mTransport.sendMessage(mx);
        }
        return;
    }

    private void parseInfoResponse(Message m) throws IOException {
        if (!mAuthMethod.equals("keyboard-interactive")) {
            throw new SSHException("Illegal info response from the client");
        }
        int n = m.getInt();
        String[] responses = new String[n];
        for (int i = 0; i < n; i++) {
            responses[i] = m.getString();
        }
        int result = mServer.checkAuthInteractiveResponse(responses);
        if (result == AuthError.CONTINUE_INTERACTIVE) {
            InteractiveQuery query = mServer.checkAuthInteractive(mUsername,
                    mSubmethods);
            if (query != null) {
                interactiveQuery(query);
                return;
            }
            result = AuthError.FAILED;
        }
        sendAuthResult(mUsername, "keyboard-interactive", result);
    }

    private void interactiveQuery(InteractiveQuery dialog) throws IOException {
        Message m = new Message();
        m.putByte(MessageType.USERAUTH_INFO_REQUEST);
        m.putString(dialog.title);
        m.putString(dialog.instructions);
        m.putString("");
        m.putInt(dialog.prompts.length);
        for (int i = 0; i < dialog.prompts.length; i++) {
            m.putString(dialog.prompts[i].text);
            m.putBoolean(dialog.prompts[i].echoResponse);
        }
        mTransport.sendMessage(m);
        mTransport.registerMessageHandler(MessageType.USERAUTH_INFO_RESPONSE,
                this);
    }

    private void parseAuthRequest(Message m) throws IOException {
        if (mAuthenticated) {
            // ignore
            return;
        }

        String username = m.getString();
        String service = m.getString();
        String method = m.getString();
        logger.debug("Auth request (type={}) service={} username={}",
                new Object[] { method, service, username });

        if (!service.equals("ssh-connection")) {
            disconnectServiceNotAvailable();
            return;
        }
        if ((mUsername != null) && !mUsername.equals(username)) {
            logger.warn("Auth rejected because the client attempted to change username in mid-flight");
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
                /*
                 * always treated as a failure, since we don't support changing
                 * passwords, but collect the list of valid auth types from the
                 * callback anyway
                 */
                logger.debug("Auth request to change passwords (rejected)");
                m.getString(); // new password
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
                logger.info("Auth rejected: public key: {}", x);
                disconnectNoMoreAuth();
                return;
            }

            // first check if this key is okay... if not, we can skip verifying
            // it
            result = mServer.checkAuthPublicKey(username, key);
            if (result != AuthError.FAILED) {
                // okay, verify it
                if (!sigAttached) {
                    /*
                     * client was just asking if this key was acceptable, before
                     * bothering to sign anything. say it's okay.
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
                if (!key.verifySSHSignature(mCrai, blob, sig)) {
                    logger.info("Auth rejected: invalid signature");
                    result = AuthError.FAILED;
                }
            }
        } else if (method.equals("keyboard-interactive")) {
            m.getString(); // lang
            List<String> l = m.getList();
            String[] submethods = l.toArray(new String[l.size()]);
            InteractiveQuery query = mServer.checkAuthInteractive(username,
                    submethods);
            if (query != null) {
                mAuthMethod = method;
                mUsername = username;
                mSubmethods = submethods;
                interactiveQuery(query);
                return;
            }
            result = AuthError.FAILED;
        } else {
            result = mServer.checkAuthNone(username);
        }

        // okay, send result
        sendAuthResult(username, method, result);
    }

    private static final int DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
    // private static final int DISCONNECT_AUTH_CANCELLED_BY_USER = 13;
    private static final int DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;

    private BaseTransport mTransport;
    private Crai mCrai;
    private BannerListener mBannerListener;
    private String mBanner;
    private ServerInterface mServer;
    private Event mAuthEvent;
    private boolean mAuthenticated;
    private int mFailCount;

    // auth info
    private String mAuthMethod;
    private String mUsername;
    private String mPassword;
    private PKey mPrivateKey;
    private InteractiveHandler mInteractiveHandler;
    private String[] mSubmethods;
}
