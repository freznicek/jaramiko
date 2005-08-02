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
 * Created on Jul 2, 2005
 */

package net.lag.jaramiko;


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
