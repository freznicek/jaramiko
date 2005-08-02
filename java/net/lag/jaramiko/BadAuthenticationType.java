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

/**
 * Exception raised when an authentication type (like password) is used, but
 * the server isn't allowing that type.  (It may only allow public-key, for
 * example.)
 * 
 * @author robey
 */
public class BadAuthenticationType
    extends SSHException
{
    /* package */
    BadAuthenticationType (String[] types)
    {
        super("Bad authentication type.");
        mAllowedTypes = types;
    }
    
    /**
     * Return the list of authentication types allowed by the server.  Possible
     * values are: <code>"none"</code>, <code>"password"</code>, and
     * <code>"publickey"</code>.
     * 
     * @return the list of auth types allowed by the server
     */
    public String[]
    getAllowedTypes ()
    {
        return mAllowedTypes;
    }
    
    
    private String[] mAllowedTypes;
    
    private static final long serialVersionUID = 0;
}
