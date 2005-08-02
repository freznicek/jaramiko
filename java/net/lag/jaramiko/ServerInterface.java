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
 * Created on Jun 27, 2005
 */

package net.lag.jaramiko;

import java.util.List;


/**
 * Interface for controlling the behavior of paramiko in server mode.
 * 
 * <p>Methods on this class are called from paramiko's primary thread, so you
 * shouldn't do too much work in them (certainly nothing that blocks or
 * sleeps).
 * 
 * @author robey
 */
public interface ServerInterface
{
    /**
     * Determine if a channel request of the given type will be granted, and
     * return one of the {@link ChannelError} codes.  This method is called
     * in server mode when the client requests a channel, after authentication
     * is complete.
     * 
     * <p>The <code>chanID</code> parameter is a small number that uniquely
     * identifies the channel within a {@link Transport}.  A {@link Channel}
     * object is not created unless this method returns
     * {@link ChannelError#SUCCESS} -- once a {@link Channel} object is
     * created, you can call {@link Channel#getID} to retrieve the channel
     * ID.
     * 
     * @param kind the kind of channel the client would like to open
     *     (usually <code>"session"</code>)
     * @param chanID ID of the channel
     * @return a success or failure code from {@link ChannelError}
     */
    public int
    checkChannelRequest (String kind, int chanID);
    
    /**
     * Return a list of authentication methods supported by the server.
     * This list is sent to clients attempting to authenticate, to inform
     * them of authentication methods that might be successful.
     * 
     * <p>The "list" is actually a string of comma-separated names of types
     * of authentication.  Possible values are:
     * <ul>
     * <li> <code>"password"</code>
     * <li> <code>"publickey"</code>
     * <li> <code>"none"</code>
     * </ul>
     * 
     * @param username the username requesting authentication
     * @return a comma-separated list of authentication types
     */
    public String
    getAllowedAuths (String username);

    /**
     * Determine if a client may open channels with no (further)
     * authentication.  The return code should be one of those listed in
     * {@link AuthError}.   
     * 
     * @param username the username of the client
     * @return an AuthError code
     */
    public int
    checkAuthNone (String username);
    
    /**
     * Determine if a given username and password supplied by the client is
     * acceptable for use in authentication.  The return code should be one
     * of those listed in {@link AuthError}.
     * 
     * @param username the username of the client
     * @param password the password given by the client
     * @return an AuthError code
     */
    public int
    checkAuthPassword (String username, String password);
    
    /**
     * Determine if a given key supplied by the client is suitable for use in
     * authentication.  The return code should be one of those listed in
     * {@link AuthError}.
     * 
     * <p>Note that you don't have to actually verify any key signature here.
     * If this method returns {@link AuthError#SUCCESS}, paramiko will do the
     * signature verification, and only accept the key if the signature is
     * valid.
     * 
     * @param username the username of the client
     * @param key the key object provided by the client
     * @return an AuthError code
     */
    public int
    checkAuthPublicKey (String username, PKey key);
    
    /**
     * Handle a global request of the given kind.  This method is called
     * in server mode and client mode, whenever the remote host makes a global
     * request.  If there are any arguments to the request, they will be in
     * <code>m</code>.
     * 
     * <p>There aren'y any useful global requests defined in the SSH2
     * protocol, aside from port forwarding, so usually this type of request
     * is an extension to the protocol.
     * 
     * <p>If the request was successful, a list of contextual data should be
     * returned, which will be attached to the response.  The list may only
     * contain objects which can be streamed in the SSH2 protocol: Integers,
     * Longs, Booleans, Bytes, BigIntegers, Strings, or byte[]s.
     * 
     * <p>If the request fails, this method should return null.
     * 
     * @param kind the name of the global request being made
     * @param m any extra arguments to the request
     * @return a list of data to attach to the response (on success), or null
     *     on failure
     */
    public List
    checkGlobalRequest (String kind, Message m);

    /**
     * Determine if a pseudo-terminal of the given dimensions (usually
     * requested for shell access) can be provided on the given channel.
     * 
     * @param c the Channel the pty request arrived on
     * @param term type of terminal requested (for example, <code>"vt100"</code>)
     * @param width width of screen in characters
     * @param height height of screen in characters
     * @param pixelWidth width of screen in pixels, if known (may be
     *     <code>0</code> if unknown)
     * @param pixelHeight height of screen in pixels, if known (may be
     *     <code>0</code> if unknown)
     * @param modes terminal modes (undocumented)
     * @return true if the pty has been allocated; false otherwise
     */
    public boolean
    checkChannelPTYRequest (Channel c, String term, int width, int height, int pixelWidth, int pixelHeight,
                            String modes);
    
    /**
     * Determine if a shell will be provided to the client on the given
     * channel.  If this method returns true, the channel should be connected
     * to the stdin/stdout of a shell (or something that acts like a shell).
     * 
     * @param c the Channel the request arrived on
     * @return true if this channel is now hooked up to a shell; false if a
     *     shell can't or won't be provided
     */
    public boolean
    checkChannelShellRequest (Channel c);
    
    /**
     * Determine if a shell command will be executed for the client.  If this
     * method returns true, the channel should be connected to the stdin,
     * stdout, and stderr of the shell command.
     * 
     * @param c the Channel the request arrived on
     * @param command the command to execute
     * @return true if this channel is now hooked up to the stdin, stdout,
     *     and stderr of the executing command; false if the command will not
     *     be executed
     */
    public boolean
    checkChannelExecRequest (Channel c, String command);
    
    /**
     * Determine if a requested subsystem will be provided to the client on
     * the given channel.  If this method returns true, all future I/O through
     * this channel will be assumed to be connected to the requested subsystem.
     * An example of a subsystem is <code>sftp</code>.
     * 
     * @param c the Channel the request arrived on
     * @param name name of the requested subsystem
     * @return true if this channel is now hooked up to the requested
     *     subsystem; false if that subsystem can't or won't be provided
     */
    public boolean
    checkChannelSubsystemRequest (Channel c, String name);

    /**
     * Determine if the pseudo-terminal on the given channel can be resized.
     * This only makes sense if a pty was previously allocated on it.
     * 
     * @param c the Channel the pty request arrived on
     * @param width width of the screen in characters
     * @param height height of the screen in characters
     * @param pixelWidth width of the screen in pixels, if known (may be
     *     <code>0</code> if unknown)
     * @param pixelHeight height of the screen in pixels, if known (may be
     *     <code>0</code> if unknown)
     * @return true if the terminal was resized, false if not
     */
    public boolean
    checkChannelWindowChangeRequest (Channel c, int width, int height, int pixelWidth, int pixelHeight);

}
