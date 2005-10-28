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
 */

package net.lag.jaramiko;


/**
 * An exception raised when an attempt to open a channel (via
 * {@link ClientTransport#openSession} or {@link ClientTransport#openChannel}) fails.
 * The exception contains an error code from the SSH server.
 * 
 * @author robey
 */
public class ChannelException
    extends SSHException
{
    public
    ChannelException (int code)
    {
        super(ChannelError.getDescription(code));
        mChannelError = code;
    }
    
    /**
     * Return the error code received from the server.  The code should be
     * one of the constants in {@link ChannelError}.
     * 
     * @return the error code from the server
     */
    public int
    getChannelError ()
    {
        return mChannelError;
    }
    
    
    private int mChannelError;
    
    static final private long serialVersionUID = 0;
}
