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
 * Created on Jul 2, 2005
 */

package net.lag.paramiko;


/**
 * Error codes returned by an SSH2 server when it rejects an authentication
 * request.  These are used by the various authentication methods in
 * {@link ServerInterface}.
 * 
 * @author robey
 */
public final class AuthError
{
    private
    AuthError ()
    {
        // forbid
    }
    
    
    /**
     * The authentication was successful, and the authentication process is
     * complete.
     */
    public static final int SUCCESS = 0;
    
    /**
     * The authentication was successful, but more stages of authentication
     * are required before authentication is complete.  In this case,
     * {@link ServerInterface#getAllowedAuths} will be called to get a list
     * of authentication methods that can be used to continue.
     */
    public static final int PARTIAL_SUCCESS = 1;
    
    /**
     * Authentication failed.
     */
    public static final int FAILED = 2;
}
