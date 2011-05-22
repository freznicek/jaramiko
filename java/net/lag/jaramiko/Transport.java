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
import java.util.List;

/**
 * Shared interface of {@link ClientTransport} and {@link ServerTransport}.
 */
public interface Transport {
    /**
     * Set the logging mechanism for this Transport. By default, log messages
     * are sent to a {@link NullLog} object.
     * 
     * @param logger
     *            the new logger to use
     */
    public void setLog(LogSink logger);

    /**
     * Set whether packet contents should be logged as they arrive or depart.
     * Normally you only want this on for serious debugging; the log traffic
     * would otherwise be huge.
     * 
     * @param dump
     *            true if packet contents should be logged; false if not
     */
    public void setDumpPackets(boolean dump);

    /**
     * Return a {@link SecurityOptions} object which can be used to tweak the
     * encryption algorithms this transport will permit, and the order of
     * preference for them. The preferred algorithms for encryption, digest
     * (hash), public key, and key exchange can be modified this way.
     * 
     * <p>
     * These preferences must be set before calling
     * {@link ClientTransport#start} or {@link ServerTransport#start} or they
     * will have no effect.
     * 
     * @return this Transport's SecurityOptions object
     */
    public SecurityOptions getSecurityOptions();

    /**
     * Return true if this session is active and has authenticated successfully.
     * For a client, it means this client has successfully authenticated to the
     * server. For a server, it means the remote client has successfully
     * authenticated to us.
     * 
     * @return true if this session is active and authenticated
     */
    public boolean isAuthenticated();

    /**
     * Return the username this connection is authenticated for. If the session
     * is not authenticated (or authentication failed), this method returns
     * null.
     * 
     * @return the username that was authenticated, or null
     */
    public String getUsername();

    /**
     * Turn on/off keepalive packets (default is off). If this is set, after
     * <code>interval</code> milliseconds without sending any data over the
     * connection, a "keepalive" packet will be sent (and ignored by the remote
     * host). This can be useful to keep connections alive over a NAT, for
     * example.
     * 
     * @param interval_ms
     *            milliseconds to wait before sending a keepalive packet (or 0
     *            to disable keepalives)
     */
    public void setKeepAlive(int interval_ms);

    /**
     * Force this session to switch to new keys. Normally this is done
     * automatically after the session hits a certain number of packets or bytes
     * sent or received, but this method gives you the option of forcing new
     * keys whenever you want. Negotiating new keys causes a pause in traffic
     * both ways as the two sides swap keys and do computations. This method
     * returns when the session has switched to new keys, or the session has
     * died mid-negotiation.
     * 
     * @param timeout_ms
     *            time (in milliseconds) to wait for renegotiation
     * @throws IOException
     *             if the renegotiation failed, or the connection was lost
     */
    public void renegotiateKeys(int timeout_ms) throws IOException;

    /**
     * Send a junk packet across the encrypted link. This is sometimes used to
     * add "noise" to a connection to confuse would-be attackers. It can also be
     * used as a keep-alive for long lived connections traversing firewalls.
     * 
     * <p>
     * If <code>bytes</code> is 0, a random number of bytes from 10 to 41 will
     * be attached.
     * 
     * @param bytes
     *            the number of random bytes to send in the payload of the
     *            ignored packet
     * @param timeout_ms
     *            time (in milliseconds) to wait for the request
     * @throws IOException
     *             if an exception occurs while sending the request
     */
    public void sendIgnore(int bytes, int timeout_ms) throws IOException;

    /**
     * Make a global request to the remote host. These are normally extensions
     * to the SSH2 protocol.
     * 
     * <p>
     * If <code>timeout_ms</code> is greater than zero, a response is requested
     * from the remote host, and this method will wait up to the timeout for a
     * response. The response will be returned as an SSH2 {@link Message}.
     * 
     * <p>
     * If <code>timeout_ms</code> is zero (or -1), no response is requested, and
     * the method returns <code>null</code> immediately.
     * 
     * @param requestName
     *            name of the request to make
     * @param parameters
     *            an optional list of objects to attach to the request (see
     *            {@link Message#putAll} for a list of objects that can be
     *            attached); <code>null</code> to attach nothing
     * @param timeout_ms
     *            0 to request no response; otherwise the maximum time to wait
     *            for a response from the server
     * @return the remote host's response, or <code>null</code> if the timeout
     *         was hit or no response was requested
     * @throws IOException
     *             if an I/O exception occurred on the socket
     */
    public Message sendGlobalRequest(String requestName, List parameters,
            int timeout_ms) throws IOException;

    /**
     * Close this session, and any open channels.
     */
    public void close();

    /**
     * Register a specific subclass of Channel to be used with the specified
     * kind. This does not need to be done for the generic "session" channel
     * kind; however, if you want to override the Channel class used for kind
     * "session" you may do so. This is generally used for implementing new
     * protocols over SSH.
     * 
     * @param kind
     *            kind of channel the class implements
     * @param factory
     *            the factory for creating channels of this type
     */
    public void registerChannelKind(String kind, ChannelFactory factory);
}
