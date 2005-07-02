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
 * Created on Jun 27, 2005
 */

package net.lag.paramiko;

import java.util.List;


/**
 * This class defines an interface for controlling the behavior of paramiko
 * in server mode.
 * 
 * Methods on this class are called from paramiko's primary thread, so you
 * shouldn't do too much work in them.  (Certainly nothing that blocks or
 * sleeps.)
 * 
 * @author robey
 */
public interface ServerInterface
{
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
